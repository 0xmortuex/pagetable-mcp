# Backlog

Real, finishable improvements - pick ONE, ship it end-to-end with tests.

- [ ] Switch `gdbstub-mcp @ git+...` to a PyPI pin once gdbstub-mcp is published (PyPI
      rejects direct URL dependencies - required before publishing this package).
- [ ] Apply PKRU to verdicts (read PKRU via the stub if exposed) for protection-key faults.
- [ ] AArch64 stage-1 tables (TTBR0/TTBR1, 4K/16K/64K granules) and RISC-V Sv39/Sv48.
- [ ] `pt_diff`: snapshot the mappings, run, and show what changed (catches "who unmapped this").
- [ ] Read MAXPHYADDR automatically (QEMU `-cpu` phys-bits via QMP `query-cpu-model-expansion`).
- [ ] Run as tools inside gdbstub-mcp too, so one gdbstub connection serves both (QEMU's
      stub takes a single client).
- [ ] EPT / nested paging for hypervisor developers.
