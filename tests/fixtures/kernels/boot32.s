# Multiboot entry + #PF handler shared by the 32-bit fixture kernels
# (2-level paging and PAE). The handler records CR2 and the error code,
# calls faulted() - a breakpoint target - and halts, so the faulting state
# stays inspectable from the debugger.
.set MAGIC, 0x1BADB002
.set FLAGS, 0x0
.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long -(MAGIC + FLAGS)

.section .bss
.align 16
stack_bottom:
.skip 16384
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    mov $stack_top, %esp
    call kmain
1:  cli
    hlt
    jmp 1b

.global pf_stub
.type pf_stub, @function
pf_stub:
    # The CPU pushed the error code; CR2 holds the faulting address.
    mov (%esp), %eax
    mov %eax, pf_error
    mov %cr2, %eax
    mov %eax, pf_addr
    call faulted
2:  cli
    hlt
    jmp 2b
