"""End to end against real QEMU running the fixture kernels.

Ground truth comes from QEMU itself: its `info tlb` monitor command (over
QMP) lists every mapping, and the kernels' #PF handler records the error
code the CPU actually pushed. Skipped when qemu-system-x86_64 is missing.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import time

import pytest

from pagetable_mcp import paging as pg
from pagetable_mcp import server as S

KERNELS = os.path.join(os.path.dirname(__file__), "fixtures", "kernels")


def _find_qemu():
    found = shutil.which("qemu-system-x86_64")
    if found:
        return found
    win = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
    return win if os.path.isfile(win) else None


QEMU = _find_qemu()
pytestmark = pytest.mark.skipif(QEMU is None, reason="qemu-system-x86_64 not installed")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port, proc, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert proc.poll() is None, f"QEMU exited early ({proc.returncode})"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"port {port} never opened")


class VM:
    def __init__(self, kernel):
        self.elf = os.path.join(KERNELS, kernel)
        self.gport, self.qport = _free_port(), _free_port()
        self.proc = subprocess.Popen(
            [QEMU, "-display", "none", "-kernel", self.elf, "-no-reboot",
             "-gdb", f"tcp:127.0.0.1:{self.gport}", "-S",
             "-qmp", f"tcp:127.0.0.1:{self.qport},server=on,wait=off"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _wait_port(self.qport, self.proc)

    def hmp(self, cmd):
        with socket.create_connection(("127.0.0.1", self.qport), timeout=10) as s:
            f = s.makefile("rwb")
            f.readline()
            f.write(b'{"execute":"qmp_capabilities"}\n')
            f.flush()
            f.readline()
            f.write(json.dumps({"execute": "human-monitor-command",
                                "arguments": {"command-line": cmd}}).encode() + b"\n")
            f.flush()
            while True:
                r = json.loads(f.readline())
                if "return" in r:
                    return r["return"]

    def kill(self):
        self.proc.kill()
        self.proc.wait()


@pytest.fixture
def vm_factory():
    vms = []

    def make(kernel):
        v = VM(kernel)
        vms.append(v)
        return v

    yield make
    for name in list(S._targets):
        S._targets.pop(name).close()
    for v in vms:
        v.kill()


def _to_ready(v):
    out = S.pt_connect("k", port=v.gport, elf=v.elf)
    assert "Physical memory reads: yes" in out and "Paging isn't enabled yet" in out
    S.pt_break("k", "ready")
    S.pt_break("k", "faulted")
    return S.pt_continue("k", 20)


def _qemu_tlb(v):
    """{vaddr: paddr} from `info tlb`. QEMU prints NX inside the physical
    column in PAE mode (8000000000605000), so bit 63 is masked off."""
    out = {}
    for line in v.hmp("info tlb").splitlines():
        m = re.match(r"([0-9a-f]+): ([0-9a-f]+) ", line)
        if m:
            out[int(m.group(1), 16)] = int(m.group(2), 16) & ~pg.NX
    return out


def _our_leaves():
    t = S._targets["k"]
    with t.physical():
        return {lf.vaddr: lf.paddr for lf in pg.leaves(t.reader(), t.control())}


KERNEL_CASES = [
    ("paging32.elf", "32-bit paging", 0x3, "0x401000",
     "supervisor write to a read-only page with CR0.WP=1: RW=0 in the PTE"),
    ("pae.elf", "PAE paging", 0x2, "0x402000", "not present: the PTE for this address has P=0"),
    ("long64.elf", "4-level paging", 0x11, "0x405000",
     "instruction fetch from a no-execute page: NX=1 in the PTE"),
]


@pytest.mark.parametrize("kernel,mode,code,addr,reason", KERNEL_CASES,
                         ids=[c[0] for c in KERNEL_CASES])
def test_mappings_match_qemu_and_fault_is_explained(vm_factory, kernel, mode, code, addr, reason):
    v = vm_factory(kernel)
    assert "breakpoint #1 (ready)" in _to_ready(v)
    assert mode in S.pt_status("k")

    # Every leaf the walker finds is exactly what QEMU's own MMU dump shows.
    assert _our_leaves() == _qemu_tlb(v)

    # Translation details.
    out = S.pt_translate("k", "0x401000", access="write")
    assert "=> physical 0x601000" in out and "read-only" in out
    assert "FAULTS - supervisor write to a read-only page" in out
    assert "physical 0x603000" in S.pt_translate("k", "0x403000")
    found = S.pt_find_phys("k", "0x600010")
    assert "0x400010" in found and "0x404010" in found and "Aliases" in found
    assert "executable" in S.pt_check("k").split("current pc", 1)[1].splitlines()[0]

    # Run into the deliberate #PF: the handler records CR2 and the error code.
    stop = S.pt_continue("k", 20)
    assert "breakpoint #2 (faulted)" in stop
    t = S._targets["k"]
    pushed = int.from_bytes(t.session.rsp.read_memory(t.session.resolve("pf_error")[0], 4), "little")
    assert pushed == code
    expl = S.pt_explain_fault("k", error_code=pushed)
    assert f"address from CR2 = {addr}" in expl
    assert f"VERDICT: faults - {reason}" in expl
    assert f"This matches the error code the CPU pushed ({code:#x})" in expl
    assert "Disconnected" in S.pt_disconnect("k")


def test_long_mode_details(vm_factory):
    v = vm_factory("long64.elf")
    _to_ready(v)
    # Higher-half mapping: canonical sign-extended address, 2 MiB global page.
    hi = S.pt_translate("k", "0xffffffff80001234")
    assert "=> physical 0x1234" in hi and "2 MiB page" in hi and "global" in hi
    # US=1 in the leaf but not in the PML4E/PDPTE above it: supervisor-only.
    # (QEMU's `info tlb` prints the leaf's U bit, which is why this matters.)
    assert "-------UW" in [ln for ln in v.hmp("info tlb").splitlines()
                           if ln.startswith("0000000000403000")][0]
    user = S.pt_translate("k", "0x403000", access="read", user=True)
    assert "supervisor-only" in user and "US=0 in the PML4E" in user
    assert "#GP" in S.pt_explain_fault("k", address="0x0000800000000000", access="read")
    mapped = S.pt_map("k")
    assert "0xffffffff80000000" in mapped and "RW- supervisor" in mapped
    checks = S.pt_check("k")
    assert "writable AND executable: 0x0-0x400000" in checks


def test_pt_map_range_and_errors(vm_factory):
    v = vm_factory("paging32.elf")
    _to_ready(v)
    m = S.pt_map("k", start="0x400000", end="0x402000")
    assert "0x00400000" in m and "0x00401000" in m and "0x00403000" not in m
    with pytest.raises(Exception, match="already exists"):
        S.pt_connect("k", port=v.gport)
    assert "isn't mapped" in S.pt_find_phys("k", "0x700000")
