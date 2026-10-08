"""A live VM: a gdbstub-mcp debug session plus physical-memory access.

Page tables hold *physical* addresses, but a gdbstub reads *virtual* memory
by default - through the very page tables being walked. QEMU has a vendor
packet, `Qqemu.PhyMemMode:1`, that switches memory reads to physical
addresses (the same approach acpi-mcp uses to read ACPI tables). Every walk
runs inside `physical()`, which switches the mode on and always switches it
back, so other memory reads keep their normal virtual meaning.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from elftools.elf.elffile import ELFFile
from gdbstub_mcp.rsp import RSPError
from gdbstub_mcp.session import Session

from .paging import Control


class TargetError(RuntimeError):
    pass


class Target:
    def __init__(self, name: str, host: str, port: int, elf: str | None,
                 maxphyaddr: int | None, timeout_s: float):
        self.session = Session(name, host, port, elf, 0, timeout_s)
        self.maxphyaddr = maxphyaddr
        self.elf = elf
        try:
            supported = self.session.rsp.request("qqemu.Supported").decode()
        except RSPError:
            supported = ""
        self.phys_capable = "PhyMemMode" in supported
        for reg in ("cr0", "cr3", "cr4"):
            try:
                self.session.layout.by_name(reg)
            except KeyError:
                self.session.close()
                raise TargetError(
                    f"this gdbstub doesn't expose {reg} - page tables can't be located. "
                    "QEMU's x86 stub does; use qemu-system-x86_64 or qemu-system-i386") from None

    def control(self) -> Control:
        s = self.session
        efer = 0
        try:
            efer = s.read_reg("efer")
        except KeyError:
            pass  # i386 targets without EFER: no NX, no long mode
        return Control(s.read_reg("cr0"), s.read_reg("cr3"), s.read_reg("cr4"), efer)

    @contextmanager
    def physical(self) -> Iterator[None]:
        if not self.phys_capable:
            raise TargetError(
                "this gdbstub can't read physical memory (no Qqemu.PhyMemMode), and page tables "
                "hold physical addresses. Use QEMU's gdbstub (-s), or a VM where the page tables "
                "are identity-mapped and reads through virtual addresses happen to match.")
        rsp = self.session.rsp
        if rsp.request("Qqemu.PhyMemMode:1") != b"OK":
            raise TargetError("QEMU refused Qqemu.PhyMemMode:1")
        try:
            yield
        finally:
            rsp.request("Qqemu.PhyMemMode:0")

    def reader(self) -> TableCache:
        return TableCache(self)

    def elf_segments(self) -> list[tuple[int, int, str]]:
        """(vaddr, size, flags) of the ELF's LOAD segments - the kernel image."""
        if self.elf is None:
            return []
        out = []
        with open(self.elf, "rb") as fh:
            for seg in ELFFile(fh).iter_segments():
                if seg["p_type"] == "PT_LOAD" and seg["p_memsz"]:
                    f = seg["p_flags"]
                    flags = ("R" if f & 4 else "-") + ("W" if f & 2 else "-") + ("X" if f & 1 else "-")
                    out.append((seg["p_vaddr"], seg["p_memsz"], flags))
        return out

    def close(self) -> None:
        self.session.close()


class TableCache:
    """Physical reads, cached by 4 KiB page for the duration of one tool call
    (a map of a large address space reads each table once)."""

    def __init__(self, target: Target):
        self.target = target
        self.pages: dict[int, bytes] = {}

    def __call__(self, addr: int, length: int) -> bytes:
        out = bytearray()
        while length > 0:
            page = addr & ~0xFFF
            if page not in self.pages:
                try:
                    self.pages[page] = self.target.session.rsp.read_memory(page, 4096)
                except RSPError as e:
                    raise TargetError(f"could not read physical page {page:#x}: {e} - a paging "
                                      f"entry points outside guest RAM?") from e
            off = addr - page
            n = min(length, 4096 - off)
            out += self.pages[page][off:off + n]
            addr += n
            length -= n
        return bytes(out)


def elf_exists(path: str | None) -> None:
    if path is not None and not os.path.isfile(path):
        raise FileNotFoundError(f"ELF not found: {path}")
