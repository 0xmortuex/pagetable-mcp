# pagetable-mcp

**Let your AI agent read the page tables, and tell you exactly why that page fault happened.**

<!-- mcp-name: io.github.0xmortuex/pagetable-mcp -->

pagetable-mcp is an [MCP](https://modelcontextprotocol.io) server that walks the x86 page
tables of a kernel running in QEMU, through QEMU's gdbstub. It shows every level of a
translation and the *effective* permissions combined across levels. It explains a #PF
in one sentence and cross-checks it against the error code the CPU pushed. It also maps
the whole address space and audits it for common bugs.

It supports every x86 paging mode: off, 32-bit (with 4 MiB PSE pages), PAE, 4-level and
5-level (LA57). You don't need a gdb binary. It works alongside
[qemu-mcp](https://github.com/0xmortuex/qemu-mcp) and
[gdbstub-mcp](https://github.com/0xmortuex/gdbstub-mcp).

## What it looks like

This is real output from the long-mode test kernel in `tests/fixtures/kernels`. The
kernel calls into a no-execute page, and its #PF handler stops at `faulted()`:

```
> pt_explain_fault
Access: supervisor execute of 0x405000
Error code 0x11: protection violation (page present), read, supervisor mode, instruction fetch
0x405000 (4level paging)
  PML4E [  0] @ 0x00101000 = 0x0000000000102023  P RW A  -> table 0x102000
  PDPTE [  0] @ 0x00102000 = 0x0000000000103023  P RW A  -> table 0x103000
  PDE   [  2] @ 0x00103010 = 0x0000000000104027  P RW US A  -> table 0x104000
  PTE   [  5] @ 0x00104028 = 0x8000000000605003  P RW NX  -> 4 KiB page at 0x605000
  => physical 0x605000 (4 KiB page; writable, supervisor-only, no-execute)

VERDICT: faults - instruction fetch from a no-execute page: NX=1 in the PTE (EFER.NXE=1)
This matches the error code the CPU pushed (0x11).
Fix: clear NX on the leaf (and every upper level) if code should run there - or this caught a jump into data.
(address from CR2 = 0x405000)
```

Permissions are combined across levels, which is where most paging bugs hide. Here the
leaf entry says US=1, but the PML4E above it doesn't, so user code can't touch the page:

```
> pt_translate 0x403000 access=read user=True
  PML4E [  0] @ 0x00101000 = 0x0000000000102023  P RW A  -> table 0x102000
  PDPTE [  0] @ 0x00102000 = 0x0000000000103023  P RW A  -> table 0x103000
  PDE   [  2] @ 0x00103010 = 0x0000000000104007  P RW US  -> table 0x104000
  PTE   [  3] @ 0x00104018 = 0x0000000000603007  P RW US  -> 4 KiB page at 0x603000
  => physical 0x603000 (4 KiB page; writable, supervisor-only, executable)
  user read: FAULTS - user-mode access to a supervisor page: US=0 in the PML4E
```

QEMU's own `info tlb` prints that page as `-------UW`, because it shows the leaf's U bit
only.

The whole address space, coalesced into runs, with physical addresses:

```
> pt_map
4-level paging (long mode); CR0.WP=1 (supervisor writes honour read-only), NX enabled (EFER.NXE)
virtual            physical            size  perms
0x0000000000000000 0x000000000000     4 MiB  RWX supervisor  (2 x 2 MiB)
0x0000000000400000 0x000000600000     4 KiB  RWX supervisor  (1 x 4 KiB)
0x0000000000401000 0x000000601000     4 KiB  R-X supervisor  (1 x 4 KiB)
0x0000000000403000 0x000000603000     4 KiB  RWX supervisor  (1 x 4 KiB)
0x0000000000404000 0x000000600000     4 KiB  R-X supervisor  (1 x 4 KiB)
0x0000000000405000 0x000000605000     4 KiB  RW- supervisor  (1 x 4 KiB)
0xffffffff80000000 0x000000000000     2 MiB  RWX supervisor  (1 x 2 MiB)
```

## Install

```bash
pip install pagetable-mcp
claude mcp add pagetable -- pagetable-mcp
```

Python 3.10+. Start QEMU with its gdbstub on and the CPU halted:

```bash
qemu-system-x86_64 -kernel kernel.elf -s -S
```

Then: `pt_connect` (pass `elf=` for symbols) → `pt_break` on a function that runs after
paging is enabled → `pt_continue` → `pt_translate` / `pt_map` / `pt_check`. For a page
fault, stop in your #PF handler and call `pt_explain_fault`. CR2 is read automatically.
Pass the error code the CPU pushed, which is at `[esp]`/`[rsp]` on the handler's first
instruction.

QEMU's gdbstub accepts **one client at a time**. If gdbstub-mcp is attached, run
`debug_disconnect` before `pt_connect`, or the other way round.

## Tools

| Tool | What it does |
|------|--------------|
| `pt_connect` / `pt_disconnect` | Attach to QEMU's gdbstub, or detach (removing breakpoints and leaving the guest running). Optional `maxphyaddr` enables the "bits above MAXPHYADDR" reserved-bit check. |
| `pt_break` / `pt_continue` / `pt_interrupt` | Just enough execution control to reach the point you care about. Breakpoints default to hardware. `pt_continue` steps over a breakpoint at the current pc first, because QEMU would otherwise report it again. |
| `pt_status` | Paging mode and CR0/CR3/CR4/EFER/CR2, decoded (WP, PSE, PAE, LA57, PCIDE, SMEP, SMAP, PKE, LME/LMA, NXE). |
| `pt_translate` | Walk one address: each level's entry address, raw value, decoded bits, and the final physical address with effective permissions. Pass `access` and `user` to ask whether that access would fault. |
| `pt_explain_fault` | Why a #PF happened: not present at level N, read-only with CR0.WP, user access to a supervisor page, NX fetch, SMEP, SMAP, a reserved bit, or a non-canonical address (that's a #GP). Checked against the pushed error code, with a fix. |
| `pt_map` | Everything mapped, coalesced into virtually- and physically-contiguous runs with the same permissions, optionally limited to a range. |
| `pt_find_phys` | Which virtual addresses map a physical address, with a note when there are aliases. |
| `pt_check` | Audit: is the current pc executable, the stack writable, any memory writable *and* executable, any kernel-image segment reachable from user mode (with `elf=`), any reserved bits set? |

## How it reads page tables

Page-table entries hold *physical* addresses, but a gdbstub reads *virtual* memory, and it
does so through the very tables being walked. QEMU has a vendor packet,
`Qqemu.PhyMemMode:1`, that switches memory reads to physical addresses.
[acpi-mcp](https://github.com/0xmortuex/acpi-mcp) uses the same approach. Every walk
switches it on and always switches it back afterwards. Tables are read a whole 4 KiB page
at a time and cached for one tool call, so mapping a 48-bit address space reads each
table only once.

## Tested against QEMU itself

`tests/test_qemu_integration.py` boots three committed fixture kernels:

- **32-bit** paging: a 4 MiB PSE page, 4 KiB pages, a read-only page and a write to it
- **PAE**: 2 MiB pages, NX, and a write to a not-present page
- **long mode**: 4-level paging, 2 MiB and 4 KiB pages, NX, a higher-half mapping, and a
  call into an NX page

For each kernel, **every mapping the walker finds must equal QEMU's own `info tlb`**,
read over QMP. The deliberate #PF must be explained with the same error code the
kernel's handler recorded from the CPU. The kernels are rebuilt by
`tests/fixtures/kernels/build.py` (`pip install ziglang`). CI runs them on Ubuntu's QEMU
and fails if they skip.

## Limits

- **x86 only:** no ARM or RISC-V page tables yet (see [BACKLOG.md](BACKLOG.md)).
- **QEMU's gdbstub:** it relies on `Qqemu.PhyMemMode`. Other stubs fail with a clear error
  instead of returning wrong data.
- **Protection keys:** decoded and displayed, but PKRU isn't applied to verdicts.
  Shadow-stack faults are decoded but not modelled.
- **MAXPHYADDR:** checked only when you pass `maxphyaddr=`, because the stub can't run
  CPUID for us.
- **QEMU quirk:** QEMU sets the Accessed bit in PAE PDPTEs. That bit isn't flagged as
  reserved, because the CPU accepts the entry.

## License

MIT
