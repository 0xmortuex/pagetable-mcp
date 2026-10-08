# 64-bit fixture kernel for pagetable-mcp. QEMU's multiboot loader only
# accepts 32-bit ELF images, so this is a 32-bit ELF whose code switches to
# long mode itself: build 4-level tables, enable PAE + EFER.LME/NXE + PG,
# far-jump into a 64-bit code segment.
#
# Layout:
#   0x0000000000000000-0x00000000003fffff  identity, supervisor RW (2 MiB pages)
#   0x0000000000400000 -> 0x600000  supervisor RW       (4 KiB)
#   0x0000000000401000 -> 0x601000  supervisor read-only
#   0x0000000000402000              not present
#   0x0000000000403000 -> 0x603000  user RW
#   0x0000000000404000 -> 0x600000  supervisor read-only alias of 0x400000
#   0x0000000000405000 -> 0x605000  supervisor RW, NX
#   0xffffffff80000000 -> 0x000000  supervisor RW, global (2 MiB, "higher half")
#
# Deliberate fault: call into the NX page -> #PF with I/D=1 (instruction fetch).
.set MAGIC, 0x1BADB002
.set FLAGS, 0x0
.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long -(MAGIC + FLAGS)

.section .bss
.align 4096
pml4:    .skip 4096
pdpt:    .skip 4096
pd:      .skip 4096
pt:      .skip 4096
pdpt_hi: .skip 4096
pd_hi:   .skip 4096
idt:     .skip 16 * 32
.align 16
stack_bottom:
.skip 16384
stack_top:
.global pf_addr
pf_addr:  .skip 8
.global pf_error
pf_error: .skip 8

.section .data
.align 8
gdt:
    .quad 0                          # null
    .quad 0x00209a0000000000         # 0x08: 64-bit code, present, DPL0
    .quad 0x0000920000000000         # 0x10: data
gdt_end:
gdtr:
    .word gdt_end - gdt - 1
    .long gdt
idtr:
    .word 16 * 32 - 1
    .long idt                        # 64-bit base; the kernel is below 4 GiB
    .long 0

.section .text
.code32
.global _start
.type _start, @function
_start:
    mov $stack_top, %esp

    # PML4[0] -> pdpt, PML4[511] -> pdpt_hi
    mov $pdpt, %eax
    or $0x3, %eax
    mov %eax, pml4
    mov $pdpt_hi, %eax
    or $0x3, %eax
    mov %eax, pml4 + 511 * 8

    # PDPT[0] -> pd ; PDPT_hi[510] -> pd_hi (0xffffffff80000000)
    mov $pd, %eax
    or $0x3, %eax
    mov %eax, pdpt
    mov $pd_hi, %eax
    or $0x3, %eax
    mov %eax, pdpt_hi + 510 * 8

    # PD[0], PD[1]: 2 MiB identity pages (P|RW|PS); PD[2] -> pt (P|RW|US)
    movl $0x00000083, pd
    movl $0x00200083, pd + 8
    mov $pt, %eax
    or $0x7, %eax
    mov %eax, pd + 16

    # PD_hi[0]: 2 MiB page at phys 0, P|RW|PS|G
    movl $0x00000183, pd_hi

    # 4 KiB leaves for 0x400000-0x405fff
    movl $0x00600003, pt + 0 * 8
    movl $0x00601001, pt + 1 * 8
    movl $0x00000000, pt + 2 * 8
    movl $0x00603007, pt + 3 * 8
    movl $0x00600001, pt + 4 * 8
    movl $0x00605003, pt + 5 * 8
    movl $0x80000000, pt + 5 * 8 + 4   # NX (bit 63)

    # CR4.PAE, CR3, EFER.LME|NXE, CR0.PG|WP
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4
    mov $pml4, %eax
    mov %eax, %cr3
    mov $0xC0000080, %ecx
    rdmsr
    or $((1 << 8) | (1 << 11)), %eax
    wrmsr
    mov %cr0, %eax
    or $((1 << 31) | (1 << 16)), %eax
    mov %eax, %cr0

    lgdt gdtr
    ljmp $0x08, $long_mode

.code64
long_mode:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $stack_top, %rsp

    # IDT[14] = pf64: 64-bit interrupt gate
    lea idt + 14 * 16, %rdi
    mov $pf64, %rax
    mov %ax, (%rdi)
    movw $0x08, 2(%rdi)
    movb $0, 4(%rdi)
    movb $0x8E, 5(%rdi)
    shr $16, %rax
    mov %ax, 6(%rdi)
    shr $16, %rax
    mov %eax, 8(%rdi)
    movl $0, 12(%rdi)
    lidt idtr

    call ready
    mov $0x405000, %rax
    call *%rax                 # NX page: #PF on the fetch
1:  cli
    hlt
    jmp 1b

.global ready
.type ready, @function
ready:
    ret

.global faulted
.type faulted, @function
faulted:
    ret

.global pf64
.type pf64, @function
pf64:
    mov (%rsp), %rax
    mov %rax, pf_error
    mov %cr2, %rax
    mov %rax, pf_addr
    call faulted
2:  cli
    hlt
    jmp 2b
