"""x86 paging: mode detection, page walks, permission checks, enumeration.

Pure logic - every function takes a `read(phys_addr, length) -> bytes`
callable, so it runs the same against a live VM (through a gdbstub in
physical-memory mode) or a dict of fake tables in a unit test.

Modes (Intel SDM vol. 3, ch. 4):

    none     CR0.PG = 0: linear address == physical address
    32bit    2 levels, 4-byte entries; PDE.PS gives a 4 MiB page if CR4.PSE
    pae      PDPTE (4 entries) -> PDE -> PTE, 8-byte entries; 2 MiB pages; NX
    4level   PML4E -> PDPTE -> PDE -> PTE; 1 GiB / 2 MiB pages; NX
    5level   PML5E added on top when CR4.LA57
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

Reader = Callable[[int, int], bytes]

# Control-register bits
CR0_WP = 1 << 16
CR0_PG = 1 << 31
CR4_PSE = 1 << 4
CR4_PAE = 1 << 5
CR4_LA57 = 1 << 12
CR4_PCIDE = 1 << 17
CR4_SMEP = 1 << 20
CR4_SMAP = 1 << 21
CR4_PKE = 1 << 22
EFER_LME = 1 << 8
EFER_LMA = 1 << 10
EFER_NXE = 1 << 11

# Entry bits
P, RW, US, PWT, PCD, A, D, PS, G = (1 << i for i in range(9))
NX = 1 << 63

ADDR_MASK_64 = 0x000F_FFFF_FFFF_F000  # bits 12..51


@dataclass(frozen=True)
class Control:
    cr0: int
    cr3: int
    cr4: int
    efer: int

    @property
    def mode(self) -> str:
        if not self.cr0 & CR0_PG:
            return "none"
        if self.efer & EFER_LMA:
            return "5level" if self.cr4 & CR4_LA57 else "4level"
        if self.cr4 & CR4_PAE:
            return "pae"
        return "32bit"

    @property
    def nxe(self) -> bool:
        return bool(self.efer & EFER_NXE) and self.mode in ("pae", "4level", "5level")

    @property
    def wp(self) -> bool:
        return bool(self.cr0 & CR0_WP)

    @property
    def smep(self) -> bool:
        return bool(self.cr4 & CR4_SMEP)

    @property
    def smap(self) -> bool:
        return bool(self.cr4 & CR4_SMAP)

    def describe(self) -> str:
        names = {
            "none": "paging off (linear == physical)",
            "32bit": "32-bit paging (2 levels" + (", 4 MiB pages via CR4.PSE)" if self.cr4 & CR4_PSE else ")"),
            "pae": "PAE paging (3 levels, 2 MiB pages)",
            "4level": "4-level paging (long mode)",
            "5level": "5-level paging (long mode, LA57)",
        }
        bits = []
        if self.mode != "none":
            bits.append("CR0.WP=" + ("1 (supervisor writes honour read-only)" if self.wp
                                     else "0 (supervisor can write read-only pages)"))
            if self.mode != "32bit":
                bits.append("NX " + ("enabled (EFER.NXE)" if self.nxe else "disabled (EFER.NXE=0)"))
            if self.smep:
                bits.append("SMEP")
            if self.smap:
                bits.append("SMAP")
            if self.cr4 & CR4_PKE:
                bits.append("protection keys (CR4.PKE)")
        return names[self.mode] + ("; " + ", ".join(bits) if bits else "")


@dataclass(frozen=True)
class LevelSpec:
    name: str
    shift: int
    index_bits: int
    entry_size: int
    large_size: int | None  # page size if PS is set here, None if PS isn't allowed


SPECS: dict[str, list[LevelSpec]] = {
    "32bit": [LevelSpec("PDE", 22, 10, 4, 1 << 22), LevelSpec("PTE", 12, 10, 4, None)],
    "pae": [LevelSpec("PDPTE", 30, 2, 8, None), LevelSpec("PDE", 21, 9, 8, 1 << 21),
            LevelSpec("PTE", 12, 9, 8, None)],
    "4level": [LevelSpec("PML4E", 39, 9, 8, None), LevelSpec("PDPTE", 30, 9, 8, 1 << 30),
               LevelSpec("PDE", 21, 9, 8, 1 << 21), LevelSpec("PTE", 12, 9, 8, None)],
}
SPECS["5level"] = [LevelSpec("PML5E", 48, 9, 8, None)] + SPECS["4level"]


@dataclass
class Level:
    name: str
    table: int
    index: int
    entry_addr: int
    raw: int
    present: bool
    flags: list[str]
    leaf: bool
    target: int  # next table, or page frame base if leaf
    page_size: int | None
    reserved: list[str] = field(default_factory=list)


@dataclass
class Walk:
    vaddr: int
    mode: str
    levels: list[Level]
    phys: int | None
    page_size: int | None
    writable: bool
    user: bool
    nx: bool
    global_: bool
    not_present_at: str | None
    reserved: list[str]
    noncanonical: bool = False
    pkey: int | None = None

    @property
    def mapped(self) -> bool:
        return self.phys is not None


def _cr3_base(ctl: Control) -> int:
    if ctl.mode == "32bit":
        return ctl.cr3 & 0xFFFF_F000
    if ctl.mode == "pae":
        return ctl.cr3 & 0xFFFF_FFE0
    return ctl.cr3 & ADDR_MASK_64


def canonical(vaddr: int, mode: str) -> bool:
    bits = {"4level": 48, "5level": 57}.get(mode)
    if bits is None:
        return True
    top = vaddr >> (bits - 1)
    return top == 0 or top == (1 << (64 - bits + 1)) - 1


def _decode_flags(raw: int, spec: LevelSpec, mode: str, leaf: bool, ctl: Control) -> list[str]:
    names: list[str] = []
    pae_pdpte = mode == "pae" and spec.name == "PDPTE"
    table = [(P, "P")] if pae_pdpte else [(P, "P"), (RW, "RW"), (US, "US")]
    table += [(PWT, "PWT"), (PCD, "PCD")]
    if not pae_pdpte:
        table.append((A, "A"))
        if leaf:
            table += [(D, "D"), (G, "G")]
    for bit, name in table:
        if raw & bit:
            names.append(name)
    if leaf and spec.large_size is not None and raw & PS:
        names.append("PS")
        if raw & (1 << 12):
            names.append("PAT")
    elif leaf and raw & PS:  # bit 7 of a 4 KiB PTE is PAT
        names.append("PAT")
    if spec.entry_size == 8 and raw & NX:
        names.append("NX")
    if leaf and ctl.cr4 & CR4_PKE and spec.entry_size == 8:
        names.append(f"PKEY={(raw >> 59) & 0xF}")
    return names


def _reserved(raw: int, spec: LevelSpec, mode: str, leaf: bool, ctl: Control,
              maxphyaddr: int | None) -> list[str]:
    out: list[str] = []
    if spec.entry_size == 8:
        if raw & NX and not ctl.nxe:
            out.append("NX (bit 63) is set but EFER.NXE=0, so bit 63 is reserved")
        if mode == "pae" and spec.name == "PDPTE":
            # Bits 1, 2 and 6-8 are reserved. Bit 5 (A) is left out: QEMU sets
            # it in PAE PDPTEs and the CPU accepts the entry, so flagging it
            # would predict faults that never happen.
            bad = raw & 0x1C6
            if bad:
                out.append(f"PAE PDPTE bits {bad:#x} are reserved (PDPTEs have no RW/US/D/PS)")
        if spec.name in ("PML4E", "PML5E") and raw & PS:
            out.append(f"PS is set in a {spec.name}, where it is reserved")
        if maxphyaddr is not None and maxphyaddr < 52:
            high = raw & (((1 << 52) - 1) & ~((1 << maxphyaddr) - 1))
            if high:
                out.append(f"address bits above MAXPHYADDR ({maxphyaddr}) are set: {high:#x}")
        if leaf and spec.large_size is not None and raw & PS:
            low = raw & (spec.large_size - 1) & ~0x1FFF  # bit 12 is PAT
            if low:
                out.append(f"the {_size(spec.large_size)} page's frame address isn't "
                           f"{_size(spec.large_size)}-aligned (bits {low:#x} must be 0)")
    elif leaf and raw & PS and spec.large_size is not None:  # 32-bit 4 MiB PDE
        if raw & (1 << 21):
            out.append("bit 21 of a 4 MiB PDE is reserved")
    return out


def walk(read: Reader, ctl: Control, vaddr: int, maxphyaddr: int | None = None) -> Walk:
    mode = ctl.mode
    if mode == "none":
        return Walk(vaddr, mode, [], vaddr, None, True, True, False, False, None, [])
    if mode in ("32bit", "pae") and vaddr >> 32:
        raise ValueError(f"{vaddr:#x} is wider than 32 bits, but the CPU is in {mode} paging")
    if not canonical(vaddr, mode):
        return Walk(vaddr, mode, [], None, None, False, False, False, False, None, [],
                    noncanonical=True)
    table = _cr3_base(ctl)
    levels: list[Level] = []
    writable = user = True
    nx = glob = False
    reserved: list[str] = []
    for i, spec in enumerate(SPECS[mode]):
        index = (vaddr >> spec.shift) & ((1 << spec.index_bits) - 1)
        entry_addr = table + index * spec.entry_size
        raw = int.from_bytes(read(entry_addr, spec.entry_size), "little")
        present = bool(raw & P)
        last = i == len(SPECS[mode]) - 1
        large = present and spec.large_size is not None and bool(raw & PS) and (
            mode != "32bit" or bool(ctl.cr4 & CR4_PSE))
        leaf = last or large
        if not present:
            levels.append(Level(spec.name, table, index, entry_addr, raw, False, [], leaf, 0, None))
            return Walk(vaddr, mode, levels, None, None, False, False, False, False,
                        spec.name, reserved)
        flags = _decode_flags(raw, spec, mode, leaf, ctl)
        res = _reserved(raw, spec, mode, leaf, ctl, maxphyaddr)
        reserved += [f"{spec.name}: {r}" for r in res]
        if res:
            # The CPU faults (RSVD=1) on the first entry with a reserved bit;
            # it never looks at the levels below.
            levels.append(Level(spec.name, table, index, entry_addr, raw, True, flags, leaf,
                                0, None, res))
            return Walk(vaddr, mode, levels, None, None, False, False, False, False,
                        None, reserved)
        if not (mode == "pae" and spec.name == "PDPTE"):
            writable &= bool(raw & RW)
            user &= bool(raw & US)
        if spec.entry_size == 8 and ctl.nxe and raw & NX:
            nx = True
        if leaf:
            size = spec.large_size if large and spec.large_size else 4096
            if mode == "32bit" and large:
                base = (raw & 0xFFC0_0000) | (((raw >> 13) & 0xFF) << 32)  # PSE-36
            elif mode == "32bit":
                base = raw & 0xFFFF_F000
            else:
                base = raw & ADDR_MASK_64 & ~(size - 1)
            glob = bool(raw & G)
            pkey = (raw >> 59) & 0xF if ctl.cr4 & CR4_PKE and spec.entry_size == 8 else None
            levels.append(Level(spec.name, table, index, entry_addr, raw, True, flags, True,
                                base, size, res))
            return Walk(vaddr, mode, levels, base + (vaddr & (size - 1)), size, writable, user,
                        nx, glob, None, reserved, pkey=pkey)
        nxt = raw & (0xFFFF_F000 if mode == "32bit" else ADDR_MASK_64)
        levels.append(Level(spec.name, table, index, entry_addr, raw, True, flags, False,
                            nxt, None, res))
        table = nxt
    raise AssertionError("unreachable: the last level is always a leaf")


# --- access checks -----------------------------------------------------------

ACCESSES = ("read", "write", "execute")


@dataclass
class Verdict:
    allowed: bool
    reason: str
    error_code: int | None  # what the CPU would push for this #PF (None if allowed / #GP)


def check_access(w: Walk, ctl: Control, access: str, user: bool, ac: bool = False) -> Verdict:
    """Would this access fault, and why? (SDM vol. 3, 4.6 Access Rights.)"""
    if access not in ACCESSES:
        raise ValueError(f"access must be one of {', '.join(ACCESSES)}")
    w_bit = 2 if access == "write" else 0
    u_bit = 4 if user else 0
    id_bit = 16 if access == "execute" and (ctl.nxe or ctl.smep) else 0
    who = "user-mode" if user else "supervisor"
    if w.mode == "none":
        return Verdict(True, "paging is off: every access goes straight to physical memory", None)
    if w.noncanonical:
        return Verdict(False, f"{w.vaddr:#x} is not canonical: this raises #GP, not #PF "
                              "(bits 63..47 must all equal bit 47, or 63..56 with LA57)", None)
    if w.not_present_at is not None:
        return Verdict(False, f"not present: the {w.not_present_at} for this address has P=0",
                       w_bit | u_bit | id_bit)
    if w.reserved:
        return Verdict(False, "a reserved bit is set (" + "; ".join(w.reserved) + ")",
                       1 | w_bit | u_bit | 8 | id_bit)
    prot = 1 | w_bit | u_bit | id_bit
    if user and not w.user:
        lvl = _first_without(w, US)
        return Verdict(False, f"{who} access to a supervisor page: US=0 in the {lvl}", prot)
    if access == "write" and not w.writable:
        lvl = _first_without(w, RW)
        if user:
            return Verdict(False, f"{who} write to a read-only page: RW=0 in the {lvl}", prot)
        if ctl.wp:
            return Verdict(False, f"supervisor write to a read-only page with CR0.WP=1: RW=0 in "
                                  f"the {lvl}", prot)
    if access == "execute":
        if w.nx:
            lvl = next(lv.name for lv in w.levels if lv.raw & NX)
            return Verdict(False, f"instruction fetch from a no-execute page: NX=1 in the {lvl} "
                                  "(EFER.NXE=1)", prot)
        if not user and w.user and ctl.smep:
            return Verdict(False, "supervisor instruction fetch from a user page with CR4.SMEP=1",
                           prot)
    if not user and w.user and ctl.smap and access != "execute" and not ac:
        return Verdict(False, f"supervisor {access} of a user page with CR4.SMAP=1 and "
                              "EFLAGS.AC=0 (use stac/clac around user-memory access)", prot)
    note = ""
    if access == "write" and not w.writable and not user and not ctl.wp:
        note = " (the page is read-only, but CR0.WP=0 lets the supervisor write it anyway)"
    return Verdict(True, f"allowed: {who} {access} succeeds{note}", None)


def _first_without(w: Walk, bit: int) -> str:
    for lv in w.levels:
        if w.mode == "pae" and lv.name == "PDPTE":
            continue
        if not lv.raw & bit:
            return lv.name
    return "walk"


def decode_error_code(code: int) -> str:
    parts = ["protection violation (page present)" if code & 1 else "page not present",
             "write" if code & 2 else "read", "user mode" if code & 4 else "supervisor mode"]
    if code & 8:
        parts.append("reserved bit set in a paging entry")
    if code & 16:
        parts.append("instruction fetch")
    if code & 32:
        parts.append("protection-key violation")
    if code & 64:
        parts.append("shadow-stack access")
    return ", ".join(parts)


def access_from_error_code(code: int) -> tuple[str, bool]:
    access = "execute" if code & 16 else ("write" if code & 2 else "read")
    return access, bool(code & 4)


# --- enumeration -------------------------------------------------------------


@dataclass(frozen=True)
class Leaf:
    vaddr: int
    paddr: int
    size: int
    writable: bool
    user: bool
    nx: bool
    global_: bool
    level: str


def _sign_extend(vaddr: int, mode: str) -> int:
    bits = {"4level": 48, "5level": 57}.get(mode)
    if bits and vaddr & (1 << (bits - 1)):
        return vaddr | ~((1 << bits) - 1) & 0xFFFF_FFFF_FFFF_FFFF
    return vaddr


def leaves(read: Reader, ctl: Control, start: int = 0, end: int | None = None) -> Iterator[Leaf]:
    """Every present leaf mapping overlapping [start, end), in address order.
    Reads each table once (whole-table reads)."""
    mode = ctl.mode
    if mode == "none":
        raise ValueError("paging is off - there are no page tables to enumerate")
    specs = SPECS[mode]
    top = 1 << (specs[0].shift + specs[0].index_bits)
    if end is None:
        end = 0xFFFF_FFFF_FFFF_FFFF + 1 if mode in ("4level", "5level") else top

    def visit(table: int, depth: int, base: int, writable: bool, user: bool,
              nx: bool) -> Iterator[Leaf]:
        spec = specs[depth]
        n = 1 << spec.index_bits
        data = read(table, n * spec.entry_size)
        span = 1 << spec.shift
        for i in range(n):
            lin = base + i * span
            va = _sign_extend(lin, mode)
            if va + span <= start or va >= end:
                continue
            raw = int.from_bytes(data[i * spec.entry_size:(i + 1) * spec.entry_size], "little")
            if not raw & P:
                continue
            pdpte = mode == "pae" and spec.name == "PDPTE"
            w = writable and (pdpte or bool(raw & RW))
            u = user and (pdpte or bool(raw & US))
            x = nx or (spec.entry_size == 8 and ctl.nxe and bool(raw & NX))
            last = depth == len(specs) - 1
            large = spec.large_size is not None and bool(raw & PS) and (
                mode != "32bit" or bool(ctl.cr4 & CR4_PSE))
            if last or large:
                if mode == "32bit" and large:
                    pa = (raw & 0xFFC0_0000) | (((raw >> 13) & 0xFF) << 32)
                elif mode == "32bit":
                    pa = raw & 0xFFFF_F000
                else:
                    pa = raw & ADDR_MASK_64 & ~(span - 1)
                yield Leaf(va, pa, span, w, u, x, bool(raw & G), spec.name)
            else:
                nxt = raw & (0xFFFF_F000 if mode == "32bit" else ADDR_MASK_64)
                yield from visit(nxt, depth + 1, lin, w, u, x)

    yield from visit(_cr3_base(ctl), 0, 0, True, True, False)


@dataclass
class Run:
    vaddr: int
    paddr: int
    size: int
    writable: bool
    user: bool
    nx: bool
    pages: int
    page_sizes: set[int]

    @property
    def perms(self) -> str:
        return ("R" + ("W" if self.writable else "-") + ("-" if self.nx else "X")
                + (" user" if self.user else " supervisor"))


def coalesce(items: Iterator[Leaf]) -> Iterator[Run]:
    """Merge leaves that are contiguous in both virtual and physical space and
    share permissions."""
    cur: Run | None = None
    for lf in items:
        if (cur is not None and lf.vaddr == cur.vaddr + cur.size
                and lf.paddr == cur.paddr + cur.size
                and (lf.writable, lf.user, lf.nx) == (cur.writable, cur.user, cur.nx)):
            cur.size += lf.size
            cur.pages += 1
            cur.page_sizes.add(lf.size)
            continue
        if cur is not None:
            yield cur
        cur = Run(lf.vaddr, lf.paddr, lf.size, lf.writable, lf.user, lf.nx, 1, {lf.size})
    if cur is not None:
        yield cur


def _size(n: int) -> str:
    for unit, div in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= div and n % div == 0:
            return f"{n // div} {unit}"
    return f"{n} B"


size_str = _size
