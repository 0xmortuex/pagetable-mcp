# Changelog

## 0.1.0 - 2026-10-08

First release.

- Paging modes: off, 32-bit (PSE 4 MiB pages, PSE-36), PAE, 4-level, 5-level (LA57).
- `pt_translate`: per-level walk with decoded entries and effective permissions combined
  across levels (WP, NX/NXE, SMEP, SMAP); optional access check.
- `pt_explain_fault`: CR2 by default, cross-checked against the pushed error code.
- `pt_map`, `pt_find_phys`, `pt_check`, `pt_status`, and minimal execution control
  (`pt_break`, `pt_continue` with step-over-breakpoint, `pt_interrupt`).
- Physical reads via QEMU's `Qqemu.PhyMemMode`, always restored.
- Tested against three real fixture kernels; every mapping must equal QEMU's `info tlb`.
