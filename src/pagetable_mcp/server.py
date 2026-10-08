"""pagetable-mcp: walk a live VM's x86 page tables and explain page faults."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from gdbstub_mcp.rsp import RSPError
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import paging as pg
from .target import Target, TargetError, elf_exists

mcp = MCPServer(
    "pagetable",
    instructions=(
        "Walk the x86 page tables of a kernel running in QEMU and explain address translation "
        "and page faults. Start QEMU with `-s -S` (gdbstub on 1234, CPU halted), then: "
        "pt_connect (pass elf= for symbols) -> pt_break on a symbol after paging is enabled -> "
        "pt_continue -> pt_status / pt_translate / pt_map / pt_check. For a #PF: stop in the "
        "handler (or anywhere after it) and call pt_explain_fault - CR2 is read automatically; "
        "pass the error code the CPU pushed if you have it. Addresses accept 0x..., symbols, "
        "symbol+off, or $reg. Note: QEMU's gdbstub takes one client, so disconnect gdbstub-mcp "
        "before pt_connect (or vice versa)."
    ),
)

_targets: dict[str, Target] = {}

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message
# to the client - anything else arrives as a bare "Error executing tool X" -
# so these are re-raised as ToolError with their text intact.
_EXPECTED = (RSPError, TargetError, KeyError, ValueError, FileNotFoundError, OSError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(str(msg)) from e

    mcp.tool()(wrapper)
    return fn


def _get(name: str) -> Target:
    t = _targets.get(name)
    if t is None:
        known = ", ".join(sorted(_targets)) or "none"
        raise TargetError(f"no session named {name!r} (active: {known}) - call pt_connect first")
    return t


def _addr(t: Target, expr: str) -> tuple[int, str | None]:
    return t.session.resolve(expr)


def _note(note: str | None) -> str:
    return f"\n({note})" if note else ""


def _label(t: Target, addr: int) -> str:
    """`<sym+off> at file:line` for addresses inside the kernel image, else
    "". Outside the image, a zero-size symbol (an assembly label) would
    otherwise "cover" everything after it: `0x405000 <pf_error+0x2f9df8>`."""
    if t.session.syms is None:
        return ""
    if not any(va <= addr < va + size for va, size, _ in t.elf_segments()):
        return ""
    w = t.session.where(addr)
    return " " + w.split(" ", 1)[1] if " " in w else ""


def _fmt_walk(t: Target, w: pg.Walk) -> list[str]:
    out = [f"{w.vaddr:#x}{_label(t, w.vaddr)} ({w.mode} paging)"]
    if w.mode == "none":
        out.append("  paging is off: physical == linear")
        return out
    if w.noncanonical:
        out.append("  NOT CANONICAL - any access raises #GP before the page tables are consulted")
        return out
    width = 8 if w.mode in ("32bit",) else 16
    for lv in w.levels:
        line = (f"  {lv.name:<6}[{lv.index:>3}] @ {lv.entry_addr:#0{10}x} = {lv.raw:#0{width + 2}x}  ")
        if not lv.present:
            line += "NOT PRESENT (P=0) - translation stops here"
        else:
            line += " ".join(lv.flags) or "-"
            if lv.reserved:
                line += "  - reserved bit set: translation stops here"
            elif lv.leaf:
                line += f"  -> {pg.size_str(lv.page_size or 4096)} page at {lv.target:#x}"
            else:
                line += f"  -> table {lv.target:#x}"
        out.append(line)
        for r in lv.reserved:
            out.append(f"         RESERVED: {r}")
    if w.phys is not None:
        perms = ("writable" if w.writable else "read-only") + ", " + (
            "user" if w.user else "supervisor-only") + ", " + (
            "no-execute" if w.nx else "executable") + (", global" if w.global_ else "")
        out.append(f"  => physical {w.phys:#x} ({pg.size_str(w.page_size or 4096)} page; {perms}"
                   + (f"; protection key {w.pkey}" if w.pkey is not None else "") + ")")
    elif w.reserved:
        out.append(f"  => NO TRANSLATION: the CPU faults (RSVD=1) at the {w.levels[-1].name}, "
                   "which has a reserved bit set")
    else:
        out.append(f"  => NOT MAPPED (the {w.not_present_at} is not present)")
    return out


@tool
def pt_connect(name: str, port: int = 1234, host: str = "127.0.0.1", elf: str | None = None,
               maxphyaddr: int | None = None, timeout_s: float = 10.0) -> str:
    """Connect to QEMU's gdbstub and register the session under `name`.

    Start QEMU with `-s -S` (or `-gdb tcp::PORT -S`); the CPU stays halted after
    connecting. elf enables symbols (break on `kmain`, translate `my_buffer`).
    maxphyaddr (e.g. 40 for QEMU's default qemu64 CPU) enables the "address bits
    above MAXPHYADDR are reserved" check; leave it unset to skip that check.
    QEMU's gdbstub accepts one client: disconnect gdbstub-mcp first if it's attached.
    """
    if name in _targets:
        raise TargetError(f"a session named {name!r} already exists - pt_disconnect it first")
    elf_exists(elf)
    if maxphyaddr is not None and not 32 <= maxphyaddr <= 52:
        raise ValueError("maxphyaddr must be between 32 and 52")
    t = Target(name, host, port, elf, maxphyaddr, timeout_s)
    _targets[name] = t
    ctl = t.control()
    lines = [f"Connected {name!r} to {host}:{port} ({t.session.layout.architecture}).",
             f"Paging: {ctl.describe()}",
             "Physical memory reads: " + ("yes (Qqemu.PhyMemMode)" if t.phys_capable
                                          else "NOT available - walks will fail"),
             t.session.describe_stop(t.session.last_stop)]
    if ctl.mode == "none":
        lines.append("Paging isn't enabled yet: pt_break on a function that runs after CR0.PG "
                     "is set, then pt_continue.")
    return "\n".join(lines)


@tool
def pt_disconnect(name: str) -> str:
    """Remove breakpoints, detach (the guest keeps running) and forget the session."""
    t = _get(name)
    s = t.session
    if s.last_stop[:1] not in (b"W", b"X"):
        if s.rsp.running:
            s.describe_stop(s.rsp.interrupt())
        for bp_id in list(s.breakpoints):
            s.remove_breakpoint(bp_id)
        s.rsp.detach()
    t.close()
    del _targets[name]
    return f"Disconnected {name!r}."


@tool
def pt_break(name: str, location: str, kind: str = "hw") -> str:
    """Set a breakpoint (default hardware: it works no matter how the code is
    mapped). location: symbol, symbol+0x10, file.c:42 or an address."""
    t = _get(name)
    bp, note = t.session.add_breakpoint(location, kind, None)
    return f"#{bp.id} {kind} breakpoint at {t.session.where(bp.address)}{_note(note)}"


def _step_over_breakpoint(t: Target) -> None:
    """QEMU re-reports a breakpoint at the current pc if you just continue, so
    (like gdb) lift it, single-step, and put it back."""
    s = t.session
    pc = s.read_reg(s.layout.pc().name)
    here = [b for b in s.breakpoints.values() if b.address == pc and b.kind in ("sw", "hw")]
    if not here:
        return
    kinds = {"sw": 0, "hw": 1}
    for b in here:
        s.rsp.clear_breakpoint(kinds[b.kind], b.address, b.length)
    try:
        s.rsp.resume(step=True)
        if s.rsp.wait_stop(s.rsp.read_timeout) is None:
            raise TargetError("the CPU did not stop after stepping over a breakpoint")
    finally:
        for b in here:
            s.rsp.set_breakpoint(kinds[b.kind], b.address, b.length)


@tool
def pt_continue(name: str, timeout_s: float = 10.0) -> str:
    """Resume until a breakpoint (or timeout_s; then it keeps running - call
    pt_interrupt). Steps over a breakpoint at the current pc first."""
    t = _get(name)
    s = t.session
    _step_over_breakpoint(t)
    s.rsp.resume()
    reply = s.rsp.wait_stop(timeout_s)
    if reply is None:
        return f"Still running after {timeout_s}s. Call pt_continue again or pt_interrupt."
    return s.describe_stop(reply) + "\nPaging: " + t.control().describe()


@tool
def pt_interrupt(name: str) -> str:
    """Halt a running target."""
    t = _get(name)
    return t.session.describe_stop(t.session.rsp.interrupt())


@tool
def pt_status(name: str) -> str:
    """Paging mode and the control registers that shape translation, decoded."""
    t = _get(name)
    ctl = t.control()
    s = t.session
    pc = s.read_reg(s.layout.pc().name)
    lines = [f"pc = {s.where(pc)}", f"mode: {ctl.describe()}",
             f"CR0 = {ctl.cr0:#x}  (PG={int(bool(ctl.cr0 & pg.CR0_PG))} WP={int(ctl.wp)})",
             f"CR3 = {ctl.cr3:#x}  (top-level table at {pg._cr3_base(ctl):#x})"
             if ctl.mode != "none" else f"CR3 = {ctl.cr3:#x}",
             f"CR4 = {ctl.cr4:#x}  (PSE={int(bool(ctl.cr4 & pg.CR4_PSE))} PAE={int(bool(ctl.cr4 & pg.CR4_PAE))} "
             f"LA57={int(bool(ctl.cr4 & pg.CR4_LA57))} PCIDE={int(bool(ctl.cr4 & pg.CR4_PCIDE))} "
             f"SMEP={int(ctl.smep)} SMAP={int(ctl.smap)} PKE={int(bool(ctl.cr4 & pg.CR4_PKE))})",
             f"EFER = {ctl.efer:#x}  (LME={int(bool(ctl.efer & pg.EFER_LME))} "
             f"LMA={int(bool(ctl.efer & pg.EFER_LMA))} NXE={int(bool(ctl.efer & pg.EFER_NXE))})"]
    try:
        lines.append(f"CR2 = {s.read_reg('cr2'):#x}  (last page-fault address)")
    except KeyError:
        pass
    return "\n".join(lines)


@tool
def pt_translate(name: str, address: str, access: str | None = None, user: bool = False) -> str:
    """Walk the page tables for one virtual address and show every level:
    where each entry was read from, its raw value and decoded bits, and the
    resulting physical address with the effective permissions (combined across
    levels). access ("read"/"write"/"execute") plus user=True/False also says
    whether that access would fault, and why."""
    t = _get(name)
    vaddr, note = _addr(t, address)
    ctl = t.control()
    with t.physical():
        w = pg.walk(t.reader(), ctl, vaddr, t.maxphyaddr)
    out = _fmt_walk(t, w)
    if access is not None:
        v = pg.check_access(w, ctl, access, user)
        out.append(f"  {('user' if user else 'supervisor')} {access}: "
                   + (v.reason if v.allowed else "FAULTS - " + v.reason))
    return "\n".join(out) + _note(note)


@tool
def pt_explain_fault(name: str, address: str | None = None, error_code: int | None = None,
                     access: str | None = None, user: bool = False) -> str:
    """Explain exactly why a page fault happened (or would happen).

    address defaults to CR2 (the faulting address the CPU recorded). error_code
    is the value the CPU pushed for the #PF - at the first instruction of your
    handler it's at [esp]/[rsp]; if you pass it, the access type and privilege
    are taken from it and the walk is cross-checked against it. Without it,
    pass access ("read"/"write"/"execute") and user.
    """
    t = _get(name)
    s = t.session
    note: str | None
    if address is None:
        try:
            vaddr = s.read_reg("cr2")
        except KeyError:
            raise TargetError("this stub doesn't expose CR2 - pass address=") from None
        note = f"address from CR2 = {vaddr:#x}"
    else:
        vaddr, note = _addr(t, address)
    if error_code is not None:
        if not 0 <= error_code < 1 << 16:
            raise ValueError("error_code must be the 16-bit #PF error code")
        acc, usr = pg.access_from_error_code(error_code)
    else:
        acc, usr = access or "read", user
    ctl = t.control()
    with t.physical():
        w = pg.walk(t.reader(), ctl, vaddr, t.maxphyaddr)
    v = pg.check_access(w, ctl, acc, usr)
    out = [f"Access: {'user' if usr else 'supervisor'} {acc} of {vaddr:#x}"]
    if error_code is not None:
        out.append(f"Error code {error_code:#x}: {pg.decode_error_code(error_code)}")
    out.extend(_fmt_walk(t, w))
    out.append("")
    if v.allowed:
        out.append("VERDICT: this access would NOT fault with the page tables as they are now: "
                   + v.reason)
        out.append("If it faulted earlier, the tables changed since (or the TLB was stale: a "
                   "mapping was changed without invlpg / a CR3 reload).")
    else:
        out.append(f"VERDICT: faults - {v.reason}")
        if error_code is not None and v.error_code is not None:
            mask = 0x1F
            if (v.error_code & mask) == (error_code & mask):
                out.append(f"This matches the error code the CPU pushed ({error_code:#x}).")
            else:
                out.append(f"MISMATCH: these tables predict error code {v.error_code:#x} "
                           f"({pg.decode_error_code(v.error_code)}), but the CPU pushed "
                           f"{error_code:#x}. The tables (or CR3) changed after the fault, or the "
                           "TLB held a stale entry.")
        out.append(_fix_hint(w, v, acc, usr, ctl))
    return "\n".join(out) + _note(note)


def _fix_hint(w: pg.Walk, v: pg.Verdict, access: str, user: bool, ctl: pg.Control) -> str:
    r = v.reason
    if w.noncanonical:
        return "Fix: the pointer itself is corrupt or was truncated/sign-extended wrongly."
    if r.startswith("not present"):
        return (f"Fix: map the page - fill the {w.not_present_at} (set P=1 and point it at a "
                "table/frame), then invlpg the address. A NULL-ish address means a bad pointer.")
    if "reserved" in r:
        return "Fix: an entry has a bit set that must be zero - usually a corrupted entry or a " \
               "physical address that isn't aligned to the page size."
    if "user-mode access to a supervisor page" in r:
        return "Fix: set US=1 in EVERY level of the walk if user code should reach it."
    if "write" in r and "read-only" in r:
        return "Fix: set RW=1 in every level (or this is a copy-on-write page doing its job)."
    if "no-execute" in r:
        return "Fix: clear NX on the leaf (and every upper level) if code should run there - " \
               "or this caught a jump into data."
    if "SMEP" in r:
        return "Fix: the kernel jumped into user memory - a corrupted function pointer, or an exploit."
    if "SMAP" in r:
        return "Fix: wrap intentional user-memory access in stac/clac."
    return ""


@tool
def pt_map(name: str, start: str | None = None, end: str | None = None, max_runs: int = 64) -> str:
    """List what's mapped, coalesced into runs of virtually- and physically-
    contiguous pages with the same permissions (like QEMU's `info mem`, but
    with physical addresses). start/end limit the range (addresses or symbols)."""
    if not 1 <= max_runs <= 4096:
        raise ValueError("max_runs must be between 1 and 4096")
    t = _get(name)
    ctl = t.control()
    lo = _addr(t, start)[0] if start else 0
    hi = _addr(t, end)[0] if end else None
    runs: list[pg.Run] = []
    truncated = False
    with t.physical():
        for run in pg.coalesce(pg.leaves(t.reader(), ctl, lo, hi)):
            if len(runs) == max_runs:
                truncated = True
                break
            runs.append(run)
    if not runs:
        return f"Nothing is mapped in that range ({ctl.describe()})."
    w = 18 if ctl.mode in ("4level", "5level") else 10
    lines = [f"{ctl.describe()}", f"{'virtual':<{w}} {'physical':<14} {'size':>9}  perms"]
    for r in runs:
        sizes = "/".join(pg.size_str(z) for z in sorted(r.page_sizes))
        lines.append(f"{r.vaddr:#0{w}x} {r.paddr:#014x} {pg.size_str(r.size):>9}  {r.perms}"
                     f"  ({r.pages} x {sizes})")
    if truncated:
        lines.append(f"... more runs not shown (max_runs={max_runs}); narrow with start/end")
    return "\n".join(lines)


@tool
def pt_find_phys(name: str, paddr: str, max_results: int = 16) -> str:
    """Which virtual addresses map this physical address? (Aliases, and
    "is this frame mapped anywhere?".)"""
    t = _get(name)
    target = int(paddr, 0)
    ctl = t.control()
    hits = []
    with t.physical():
        for lf in pg.leaves(t.reader(), ctl):
            if lf.paddr <= target < lf.paddr + lf.size:
                hits.append((lf.vaddr + (target - lf.paddr), lf))
                if len(hits) >= max_results:
                    break
    if not hits:
        return f"Physical {target:#x} isn't mapped at any virtual address."
    lines = [f"Physical {target:#x} is mapped at {len(hits)} virtual address(es):"]
    for va, lf in hits:
        perms = pg.Run(lf.vaddr, lf.paddr, lf.size, lf.writable, lf.user, lf.nx, 1, {lf.size}).perms
        lines.append(f"  {va:#x}  ({pg.size_str(lf.size)} page via {lf.level}; {perms})")
    if len(hits) > 1:
        lines.append("Aliases: a write through one is visible through the others; if their "
                     "permissions differ, the most permissive one is the real protection.")
    return "\n".join(lines)


@tool
def pt_check(name: str) -> str:
    """Audit the page tables for common bugs: the executing code not mapped
    (or not executable), the stack not mapped, writable+executable memory,
    kernel image pages reachable from user mode, and reserved bits set."""
    t = _get(name)
    s = t.session
    ctl = t.control()
    if ctl.mode == "none":
        return "Paging is off - nothing to check."
    pc = s.read_reg(s.layout.pc().name)
    sp = s.read_reg(s.layout.sp().name)
    findings: list[str] = []
    ok: list[str] = []
    with t.physical():
        read = t.reader()
        pc_v = pg.check_access(pg.walk(read, ctl, pc, t.maxphyaddr), ctl, "execute", False)
        (ok if pc_v.allowed else findings).append(
            f"current pc {s.where(pc)}: " + ("executable" if pc_v.allowed else pc_v.reason))
        sp_v = pg.check_access(pg.walk(read, ctl, max(sp - 8, 0), t.maxphyaddr), ctl, "write", False)
        (ok if sp_v.allowed else findings).append(
            f"stack pointer {sp:#x}: " + ("writable" if sp_v.allowed else sp_v.reason))
        runs = list(pg.coalesce(pg.leaves(read, ctl)))
        reserved_leaves = []
        for lf in pg.leaves(read, ctl):
            w = pg.walk(read, ctl, lf.vaddr, t.maxphyaddr)
            if w.reserved:
                reserved_leaves.append((lf.vaddr, w.reserved))
                if len(reserved_leaves) >= 8:
                    break
    wx = [r for r in runs if r.writable and not r.nx]
    if ctl.nxe:
        for r in wx[:8]:
            findings.append(f"writable AND executable: {r.vaddr:#x}-{r.vaddr + r.size:#x} "
                            f"({pg.size_str(r.size)}) - set NX on data")
    else:
        ok.append("no NX available in this mode (or EFER.NXE=0): every writable page is "
                  "also executable - W^X can't be enforced")
    segs = t.elf_segments()
    for r in runs:
        if not r.user:
            continue
        for va, size, flags in segs:
            if r.vaddr < va + size and va < r.vaddr + r.size:
                findings.append(f"kernel image segment {va:#x}-{va + size:#x} ({flags}) is "
                                f"user-accessible via the run at {r.vaddr:#x} - set US=0")
    if not segs:
        user_runs = [r for r in runs if r.user]
        if user_runs:
            ok.append(f"{len(user_runs)} user-accessible run(s) (pass elf= to check none of them "
                      "covers the kernel image): "
                      + ", ".join(f"{r.vaddr:#x}+{pg.size_str(r.size)}" for r in user_runs[:6]))
    for va, res in reserved_leaves:
        findings.append(f"reserved bits in the walk for {va:#x}: " + "; ".join(res))
    out = [f"{ctl.describe()}", f"{len(runs)} mapped run(s)."]
    out += ["PROBLEMS:"] + [f"  - {f}" for f in findings] if findings else ["No problems found."]
    out += ["OK / notes:"] + [f"  - {o}" for o in ok]
    return "\n".join(out)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
