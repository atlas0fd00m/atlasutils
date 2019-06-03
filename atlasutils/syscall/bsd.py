'''
syscall calling conventions:
    x86-32 [Free|Open|Net|DragonFly]BSD UNIX System Call convention:
    Parameters are passed on the stack. Push the parameters (last parameter pushed first) on to the stack. Then push an additional 32-bit of dummy data (Its not actually dummy data. refer to following link for more info) and then give a system call instruction int $0x80
    http://www.int80h.org/bsdasm/#default-calling-convention
'''
