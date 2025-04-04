#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    // Desired memory address
    void *desired_addr = (void *)0x400000000;

    // Call mmap to map the memory region
    void *mapped_addr = mmap((void *)0x400000000, 4096, 0x7, 0x22, 0xffffffffffffffff, 0);
    // 0x7 = PROT_READ | PROT_WRITE | PROT_EXEC
    // 0x32 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED

    if (mapped_addr == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // Verify the address
    if (mapped_addr != (void *)0x400000000) {
        fprintf(stderr, "mmap did not return the expected address\n");
        munmap(mapped_addr, 4096);
        exit(EXIT_FAILURE);
    }

    // Example usage of the allocated memory
    char *shellcode = (char *)mapped_addr;
    shellcode[0] = '\xc3';  // ret instruction in x86

    // Cast to function pointer and call it (for demonstration purposes)
    void (*func)() = (void (*)())shellcode;
    func();

    // Clean up
    munmap(mapped_addr, 4096);
    return 0;
}
