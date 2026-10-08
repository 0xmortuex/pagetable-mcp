/* 32-bit fixture kernel for pagetable-mcp: builds page tables, enables
 * paging, stops at ready() for inspection, then makes one deliberate page
 * fault that the #PF handler records before calling faulted().
 *
 * Built twice: without PAE (2-level, a 4 MiB PSE page) and with -DPAE
 * (3-level, 2 MiB pages, NX). Layout, identical in both:
 *
 *   0x00000000-0x003fffff  identity, supervisor RW (large pages) - kernel at 1 MiB
 *   0x00400000 -> 0x00600000  supervisor RW
 *   0x00401000 -> 0x00601000  supervisor read-only
 *   0x00402000                not present
 *   0x00403000 -> 0x00603000  user RW
 *   0x00404000 -> 0x00600000  supervisor read-only alias of 0x400000
 *   0x00405000 -> 0x00605000  supervisor RW, NX            (PAE only)
 *
 * Deliberate fault: non-PAE writes to the read-only page (P=1 W=1, CR0.WP);
 * PAE writes to the not-present page (P=0 W=1).
 */
#include <stdint.h>

#define P   0x001u
#define RW  0x002u
#define US  0x004u
#define PS  0x080u

volatile uint32_t pf_addr;
volatile uint32_t pf_error;

struct __attribute__((packed)) idt_gate {
    uint16_t off_lo, sel;
    uint8_t zero, type;
    uint16_t off_hi;
};
struct __attribute__((packed)) idtr { uint16_t limit; uint32_t base; };

static struct idt_gate idt[32];
extern void pf_stub(void);

__attribute__((noinline)) void ready(void) { __asm__ volatile("" ::: "memory"); }
__attribute__((noinline)) void faulted(void) { __asm__ volatile("" ::: "memory"); }

static void install_pf_handler(void) {
    uint16_t cs;
    __asm__ volatile("mov %%cs, %0" : "=r"(cs));
    uint32_t h = (uint32_t)pf_stub;
    idt[14].off_lo = (uint16_t)h;
    idt[14].sel = cs;
    idt[14].zero = 0;
    idt[14].type = 0x8E; /* present, DPL0, 32-bit interrupt gate */
    idt[14].off_hi = (uint16_t)(h >> 16);
    static struct idtr r;
    r.limit = sizeof(idt) - 1;
    r.base = (uint32_t)idt;
    __asm__ volatile("lidt %0" : : "m"(r));
}

#ifndef PAE
static uint32_t pd[1024] __attribute__((aligned(4096)));
static uint32_t pt[1024] __attribute__((aligned(4096)));

static void setup_paging(void) {
    pd[0] = 0x00000000u | P | RW | PS;   /* 4 MiB identity page */
    pd[1] = (uint32_t)pt | P | RW | US;  /* table for 0x400000; leaves decide */
    pt[0] = 0x00600000u | P | RW;
    pt[1] = 0x00601000u | P;
    pt[2] = 0;
    pt[3] = 0x00603000u | P | RW | US;
    pt[4] = 0x00600000u | P;
    uint32_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 1u << 4; /* PSE */
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr4));
    __asm__ volatile("mov %0, %%cr3" : : "r"((uint32_t)pd));
}
#define FAULT_ADDR 0x00401000u
#else
#define NX_HI 0x80000000u
static uint64_t pdpt[4] __attribute__((aligned(32)));
static uint64_t pd[512] __attribute__((aligned(4096)));
static uint64_t pt[512] __attribute__((aligned(4096)));

static void setup_paging(void) {
    pdpt[0] = (uint32_t)pd | P;                      /* PDPTEs have no RW/US */
    pd[0] = 0x00000000u | P | RW | PS;               /* 2 MiB identity */
    pd[1] = 0x00200000u | P | RW | PS;               /* 2 MiB identity */
    pd[2] = (uint32_t)pt | P | RW | US;
    pt[0] = 0x00600000u | P | RW;
    pt[1] = 0x00601000u | P;
    pt[2] = 0;
    pt[3] = 0x00603000u | P | RW | US;
    pt[4] = 0x00600000u | P;
    pt[5] = ((uint64_t)NX_HI << 32) | 0x00605000u | P | RW;
    /* EFER.NXE (bit 11), MSR 0xC0000080 */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000080u));
    lo |= 1u << 11;
    __asm__ volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(0xC0000080u));
    uint32_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 1u << 5; /* PAE */
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr4));
    __asm__ volatile("mov %0, %%cr3" : : "r"((uint32_t)pdpt));
}
#define FAULT_ADDR 0x00402000u
#endif

void kmain(void) {
    install_pf_handler();
    setup_paging();
    uint32_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1u << 31) | (1u << 16); /* PG, WP */
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0));
    ready();
    *(volatile uint32_t *)FAULT_ADDR = 0x1234;
}
