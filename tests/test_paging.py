"""Pure page-walk logic against synthetic tables in a fake physical memory."""

import pytest

from pagetable_mcp import paging as pg
from pagetable_mcp.paging import NX, PS, P, RW, US, G


class Mem:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}

    def put(self, addr: int, value: int, size: int) -> None:
        for i, b in enumerate(value.to_bytes(size, "little")):
            self.data[addr + i] = b

    def __call__(self, addr: int, length: int) -> bytes:
        return bytes(self.data.get(addr + i, 0) for i in range(length))


CR0 = pg.CR0_PG | pg.CR0_WP | 1


def long_mode(**extra_cr4: int) -> tuple[Mem, pg.Control]:
    """4-level: 0x0 identity 2 MiB (supervisor RW), 0x200000 table with
    4 KiB leaves, 1 GiB page at 0x40000000, a high-half 2 MiB page."""
    m = Mem()
    pml4, pdpt, pd, pt, pdpt_hi, pd_hi = (0x10000 + i * 0x1000 for i in range(6))
    m.put(pml4 + 0 * 8, pdpt | P | RW | US, 8)
    m.put(pml4 + 511 * 8, pdpt_hi | P | RW, 8)
    m.put(pdpt + 0 * 8, pd | P | RW | US, 8)
    m.put(pdpt + 1 * 8, 0x40000000 | P | RW | PS, 8)            # 1 GiB page
    m.put(pd + 0 * 8, 0x0 | P | RW | PS, 8)                     # 2 MiB supervisor
    m.put(pd + 1 * 8, pt | P | RW | US, 8)
    m.put(pt + 0 * 8, 0x800000 | P | RW | US, 8)                # user RW
    m.put(pt + 1 * 8, 0x801000 | P | US, 8)                     # user RO
    m.put(pt + 2 * 8, 0x802000 | P | RW | US | NX, 8)           # user NX
    m.put(pt + 3 * 8, 0x803000 | P | RW, 8)                     # supervisor RW
    m.put(pt + 4 * 8, 0x800000 | P | US, 8)                     # alias of 0x200000, RO
    m.put(pdpt_hi + 510 * 8, pd_hi | P | RW, 8)
    m.put(pd_hi + 0, 0x0 | P | RW | PS | G, 8)
    cr4 = pg.CR4_PAE | sum(extra_cr4.values())
    efer = pg.EFER_LME | pg.EFER_LMA | pg.EFER_NXE
    return m, pg.Control(CR0, pml4, cr4, efer)


def test_mode_detection():
    assert pg.Control(0x11, 0, 0, 0).mode == "none"
    assert pg.Control(CR0, 0, pg.CR4_PSE, 0).mode == "32bit"
    assert pg.Control(CR0, 0, pg.CR4_PAE, 0).mode == "pae"
    assert pg.Control(CR0, 0, pg.CR4_PAE, pg.EFER_LMA).mode == "4level"
    assert pg.Control(CR0, 0, pg.CR4_PAE | pg.CR4_LA57, pg.EFER_LMA).mode == "5level"
    # NX only exists with 8-byte entries
    assert not pg.Control(CR0, 0, pg.CR4_PSE, pg.EFER_NXE).nxe


def test_long_mode_walks_every_page_size():
    m, ctl = long_mode()
    w = pg.walk(m, ctl, 0x123456)
    assert [lv.name for lv in w.levels] == ["PML4E", "PDPTE", "PDE"]
    assert w.page_size == 2 << 20 and w.phys == 0x123456
    w = pg.walk(m, ctl, 0x200234)
    assert w.levels[-1].name == "PTE" and w.phys == 0x800234 and w.user
    w = pg.walk(m, ctl, 0x40000000 + 0x12345678)
    assert w.page_size == 1 << 30 and w.phys == 0x40000000 + 0x12345678
    w = pg.walk(m, ctl, 0xFFFFFFFF80001234)
    assert w.phys == 0x1234 and w.global_ and not w.user


def test_effective_permissions_combine_across_levels():
    m, ctl = long_mode()
    # The high-half PML4E has no US, so even a US leaf would be supervisor-only.
    assert not pg.walk(m, ctl, 0xFFFFFFFF80000000).user
    assert not pg.walk(m, ctl, 0x201000).writable          # leaf RW=0
    assert pg.walk(m, ctl, 0x202000).nx


def test_not_present_and_noncanonical():
    m, ctl = long_mode()
    w = pg.walk(m, ctl, 0x205000)
    assert w.not_present_at == "PTE" and not w.mapped
    v = pg.check_access(w, ctl, "write", False)
    assert not v.allowed and v.error_code == 0x2
    w = pg.walk(m, ctl, 0x0000_8000_0000_0000)
    assert w.noncanonical
    v = pg.check_access(w, ctl, "read", False)
    assert "#GP" in v.reason and v.error_code is None


@pytest.mark.parametrize("vaddr,access,user,allowed,code,phrase", [
    (0x200000, "write", True, True, None, "allowed"),
    (0x201000, "write", True, False, 0x7, "read-only"),
    (0x201000, "write", False, False, 0x3, "CR0.WP=1"),
    (0x202000, "execute", True, False, 0x15, "no-execute"),
    (0x203000, "read", True, False, 0x5, "supervisor page"),
    (0x203000, "write", False, True, None, "allowed"),
])
def test_access_matrix(vaddr, access, user, allowed, code, phrase):
    m, ctl = long_mode()
    v = pg.check_access(pg.walk(m, ctl, vaddr), ctl, access, user)
    assert v.allowed is allowed and phrase in v.reason
    if code is not None:
        assert v.error_code == code


def test_wp_off_lets_the_supervisor_write_read_only_pages():
    m, ctl = long_mode()
    ctl = pg.Control(ctl.cr0 & ~pg.CR0_WP, ctl.cr3, ctl.cr4, ctl.efer)
    v = pg.check_access(pg.walk(m, ctl, 0x201000), ctl, "write", False)
    assert v.allowed and "CR0.WP=0" in v.reason


def test_smep_and_smap():
    m, ctl = long_mode(smep=pg.CR4_SMEP, smap=pg.CR4_SMAP)
    w = pg.walk(m, ctl, 0x200000)                       # a user page
    assert "SMEP" in pg.check_access(w, ctl, "execute", False).reason
    v = pg.check_access(w, ctl, "read", False)
    assert not v.allowed and "SMAP" in v.reason
    assert pg.check_access(w, ctl, "read", False, ac=True).allowed


def test_reserved_bits():
    m, ctl = long_mode()
    m.put(0x10000 + 2 * 8, 0x50000 | P | RW | PS, 8)    # PS in a PML4E
    w = pg.walk(m, ctl, 2 << 39)
    assert any("PS is set in a PML4E" in r for r in w.reserved)
    v = pg.check_access(w, ctl, "read", False)
    assert not v.allowed and v.error_code is not None and v.error_code & 8
    # NX set while EFER.NXE=0 is a reserved bit
    ctl_nonx = pg.Control(ctl.cr0, ctl.cr3, ctl.cr4, ctl.efer & ~pg.EFER_NXE)
    assert any("EFER.NXE=0" in r for r in pg.walk(m, ctl_nonx, 0x202000).reserved)
    # a 2 MiB page whose frame isn't 2 MiB aligned
    m.put(0x12000 + 3 * 8, 0x301000 | P | RW | PS, 8)
    assert any("isn't 2 MiB-aligned" in r for r in pg.walk(m, ctl, 3 << 21).reserved)
    # bits above MAXPHYADDR
    m.put(0x13000 + 7 * 8, (1 << 45) | P | RW, 8)
    assert any("MAXPHYADDR (40)" in r for r in pg.walk(m, ctl, 0x207000, maxphyaddr=40).reserved)


def test_32bit_paging_and_pse36():
    m = Mem()
    m.put(0x1000 + 0 * 4, 0x0 | P | RW | PS, 4)                       # 4 MiB
    m.put(0x1000 + 1 * 4, 0x2000 | P | RW | US, 4)
    m.put(0x2000 + 1 * 4, 0x601000 | P, 4)
    m.put(0x1000 + 2 * 4, 0x00C00000 | (0x3 << 13) | P | RW | PS, 4)  # PSE-36: phys bits 32-33
    ctl = pg.Control(CR0, 0x1000, pg.CR4_PSE, 0)
    assert pg.walk(m, ctl, 0x123456).phys == 0x123456
    w = pg.walk(m, ctl, 0x401234)
    assert w.phys == 0x601234 and not w.writable and not w.user
    assert pg.walk(m, ctl, 0x800000).phys == 0x3_00C0_0000
    with pytest.raises(ValueError, match="wider than 32 bits"):
        pg.walk(m, ctl, 1 << 32)
    # Without CR4.PSE, PS in a PDE is ignored: it's a table pointer.
    ctl_nopse = pg.Control(CR0, 0x1000, 0, 0)
    assert pg.walk(m, ctl_nopse, 0x0).levels[-1].name == "PTE"


def test_pae_pdpte_accessed_bit_is_not_reserved():
    # QEMU sets bit 5 in PAE PDPTEs; the CPU accepts the entry.
    m = Mem()
    m.put(0x1000, 0x2000 | P | 0x20, 8)
    m.put(0x2000, 0x0 | P | RW | PS, 8)
    ctl = pg.Control(CR0, 0x1000, pg.CR4_PAE, 0)
    assert pg.walk(m, ctl, 0x1000).reserved == []
    m.put(0x1000, 0x2000 | P | RW, 8)  # RW in a PAE PDPTE is reserved
    assert pg.walk(m, ctl, 0x1000).reserved


def test_5level():
    m = Mem()
    m.put(0x1000 + 1 * 8, 0x2000 | P | RW, 8)          # PML5[1] covers 1 << 48
    m.put(0x2000, 0x3000 | P | RW, 8)
    m.put(0x3000, 0x4000 | P | RW, 8)
    m.put(0x4000, 0x0 | P | RW | PS, 8)
    ctl = pg.Control(CR0, 0x1000, pg.CR4_PAE | pg.CR4_LA57, pg.EFER_LMA)
    w = pg.walk(m, ctl, (1 << 48) + 0x1234)
    assert [lv.name for lv in w.levels] == ["PML5E", "PML4E", "PDPTE", "PDE"]
    assert w.phys == 0x1234
    assert pg.canonical(1 << 48, "5level") and not pg.canonical(1 << 48, "4level")


def test_leaves_and_coalesce():
    m, ctl = long_mode()
    lv = list(pg.leaves(m, ctl))
    assert lv[0].vaddr == 0 and lv[0].size == 2 << 20
    assert lv[-1].vaddr == 0xFFFFFFFF80000000 and lv[-1].global_
    runs = list(pg.coalesce(pg.leaves(m, ctl, 0x200000, 0x205000)))
    # 0x200000 RW user, 0x201000 RO, 0x202000 NX, 0x203000 supervisor, 0x204000 RO alias
    assert [r.perms for r in runs] == ["RWX user", "R-X user", "RW- user", "RWX supervisor",
                                       "R-X user"]
    with pytest.raises(ValueError, match="paging is off"):
        list(pg.leaves(m, pg.Control(0x11, 0, 0, 0)))


def test_coalesce_merges_contiguous_runs():
    m = Mem()
    m.put(0x1000, 0x2000 | P | RW, 8)
    for i in range(4):
        m.put(0x2000 + i * 8, (i << 21) | P | RW | PS, 8)
    ctl = pg.Control(CR0, 0x1000, pg.CR4_PAE, 0)
    runs = list(pg.coalesce(pg.leaves(m, ctl)))
    assert len(runs) == 1 and runs[0].size == 8 << 20 and runs[0].pages == 4


def test_error_code_helpers():
    assert pg.decode_error_code(0x3) == "protection violation (page present), write, supervisor mode"
    assert pg.access_from_error_code(0x15) == ("execute", True)
    assert pg.access_from_error_code(0x2) == ("write", False)
    assert "reserved bit" in pg.decode_error_code(0x9)
