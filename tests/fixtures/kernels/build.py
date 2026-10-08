"""Rebuild the fixture kernels (committed, so tests need no cross compiler).

    paging32.elf  32-bit, 2-level paging with a 4 MiB PSE page
    pae.elf       32-bit, PAE 3-level paging, 2 MiB pages, NX
    long64.elf    64-bit long mode, 4-level paging, 2 MiB + 4 KiB pages, NX,
                  a higher-half mapping (a 32-bit ELF that switches itself)

Requires: pip install ziglang
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ZIG = [sys.executable, "-m", "ziglang", "cc"]
T = ["-target", "x86-freestanding-none"]
CFLAGS = ["-ffreestanding", "-fno-pie", "-fno-stack-protector", "-fno-sanitize=undefined",
          "-O0", "-g", "-fno-omit-frame-pointer", "-mno-sse", "-mno-mmx"]
LINK = ["-nostdlib", "-static", "-no-pie", "-Wl,-T,linker.ld", "-Wl,--build-id=none"]


def run(*args: str) -> None:
    subprocess.run([*ZIG, *T, *args], check=True, cwd=HERE)


def build32(out: str, defines: list[str]) -> None:
    run(*CFLAGS, *defines, "-c", "kernel32.c", "-o", "k.o")
    run("-c", "boot32.s", "-o", "b.o")
    run(*LINK, "-o", out, "b.o", "k.o")


build32("paging32.elf", [])
build32("pae.elf", ["-DPAE"])
run("-c", "long64.s", "-o", "l.o")
run(*LINK, "-o", "long64.elf", "l.o")
for f in ("k.o", "b.o", "l.o"):
    os.remove(os.path.join(HERE, f))
print("built paging32.elf, pae.elf, long64.elf")
