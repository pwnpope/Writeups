import gdb

class FindSyscall(gdb.Command):
    """Find syscall instructions in the specified memory range."""

    def __init__(self):
        super(FindSyscall, self).__init__("findsyscall", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = arg.split()
        if len(args) != 2:
            print("Usage: finds syscall start_address end_address")
            return
        
        start_addr = int(args[0], 16)
        end_addr = int(args[1], 16)

        try:
            memory = gdb.selected_inferior().read_memory(start_addr, end_addr - start_addr)
        except gdb.MemoryError as e:
            print(f"Memory error: {e}")
            return
        
        syscall_opcode = b'\x0f\x05'

        for i in range(len(memory) - len(syscall_opcode) + 1):
            if memory[i:i+len(syscall_opcode)] == syscall_opcode:
                print(f"syscall found at: 0x{start_addr + i:x}")

FindSyscall()
