# RE

```c
int hashing_alg(char param_1,char param_2,int param_3)

{
  char char_diff;
  long in_FS_OFFSET;
  long local_28;
  undefined8 local_20;
  long cookie;
  
  cookie = *(long *)(in_FS_OFFSET + 0x28);
  char_diff = (char)((int)param_1 - (int)param_2);
  if ((int)param_1 - (int)param_2 < 1) {
    char_diff = -char_diff;
  }
  local_20 = 0;
  local_28 = (long)(char_diff * param_3);
  syscall();
  if (cookie != *(long *)(in_FS_OFFSET + 0x28)) {
    /* WARNING: Subroutine does not return */
    __stack_chk_fail(&local_28,0);
  }
  return (int)char_diff;
}
```
- subtracts one character from the other and inverts it if its negative.
- after that it `syscall` sleeps for the number of seconds that the char differs by.

```c
int chk_passwd(long param_1,undefined4 param_2)

{
  FILE *__stream;
  size_t length;
  long in_FS_OFFSET;
  int hash;
  int indx;
  char buf [72];
  long cookie;
  
  cookie = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  fread(buf,1,64,__stream);
  fclose(__stream);
  hash = 0;
  for (indx = 0;
      ((length = strlen(buf), (ulong)(long)indx < length && (hash == 0)) &&
      (hash = hashing_alg((int)*(char *)(param_1 + indx),(int)buf[indx],param_2), buf[indx] != '}'))
      ; indx = indx + 1) {
  }
  if (cookie == *(long *)(in_FS_OFFSET + 0x28)) {
    return hash;
  }
/* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
- iteratively applies a `hashing_alg` function to each character from `param_1` and the corresponding character in `buf`, combined with `param_2`. The loop continues until either the hash is non-zero or the end of the flag, indicated by '}', is encountered. The function returns the result of the `hashing_alg`.

```c
undefined8 main(undefined4 param_1)

{
  int check;
  long in_FS_OFFSET;
  char usr_input [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Time for a classic! i\'m not going to GIVE you the flag, instead you give me the flag and I\' ll tell you if its right or wrong!");
  fgets(usr_input,64,stdin);
  check = chk_passwd(usr_input,param_1);
  if (check == 0) {
    puts("Hey you got it! nice work!");
  }
  else {
    puts("wrong password! cya");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
- check whether you enter the right flag or not.

---

# solution

```python
#!/usr/bin/python3  
from pwn import *  
import time  
  
  
flag = b"flag{i_wouldve_used_argon".split()  
  
  
try:  
   for i in range(64):  
       with context.quiet:  
           io = remote("184.72.87.9", 8006)  
          
       start = time.time()  
  
       io.sendlineafter(b"\n", b"".join(flag) + b"0")  
       io.recvall()  
  
       end = time.time()  
       total_time = end - start  
          
       char = chr((ord(b"0")) + int(total_time)).encode()  
          
       flag.append(char)  
       print(b"".join(flag))  
  
except Exception as e:  
   print(e, " ", b"".join(flag))
```