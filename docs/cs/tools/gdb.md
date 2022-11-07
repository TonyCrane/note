---
comment: True
counter: True
---

# gdb 相关备忘

!!! abstract
    和 gdb 相关的一些指令备忘、插件安装方式等

## gdb 命令
### 运行
- `(gdb) run` 直接运行 (r)
- `(gdb) continue` 继续运行 (c)
- `(gdb) step` 运行到下一条源码 (s)
- `(gdb) stepi` 运行到下一条指令 (si)
- `(gdb) next` 单步运行，跳过函数 (n)
- `(gdb) finish` 运行完当前函数 (fin)
- `(gdb) attach <pid>` 连接程序
- `(gdb) detach` 从当前程序断连
- `(gdb) target remote localhost:1234` 连接 qemu

### 断点
- `(gdb) break main` 断在符号处 (b)
- `(gdb) break *0x....` 断在地址
- `(gdb) info breakpoints` 查看断点及状态 (i b)
- `(gdb) delete / clear` 清除所有断点 (d/cl)
- `(gdb) delete <breakpoint#>` 删除某一断点（从 i b 得来断点号）
- `(gdb) clear ...` 清除某一符号、地址处的断点
- `(gdb) disable <breakpoint#>` 禁用某一断点
- `(gdb) enable <breakpoint#>` 启用某一断点
- `(gdb) watch ...` 在某处增加观察点，delete、enable、disable 与断点共用
- `(gdb) break/watch <where> if <condition>` 如果条件满足则断
- `(gdb) condition <breakpoint#> <condition>` 更改条件

### 调用栈
- `(gdb) backtrace` 查看调用栈 (bt)
- `(gdb) frame` 查看当前帧栈
- `(gdb) up/down` 移动当前帧栈（向 main / 远离 main）
- `(gdb) info locals` 查看当前帧栈变量
- `(gdb) info args` 查看函数参数

### 查看寄存器/变量/内存
- `(gdb) print/format <what>`
    - `format`
        - a: pointer
        - c: int -> char
        - d: signed decimal
        - f: floating point number
        - o: int -> octal
        - s: treat as string
        - t: int -> bin
        - u: unsigned decimal
        - x: int -> hex
    - `<what>`
        - 可以是类 C 表达式
        - 可以是 file_name::variable_name
        - 可以是 function::variable_name
        - 可以是 {type}address
        - 可以是 $register
- `(gdb) display/format <what>`
- `(gdb) undisplay <display#>`
- `(gdb) enable display <display#>`
- `(gdb) disable display <display#>`
- `(gdb) x/nfu <address>` 显示内存
    - n 表示查找、打印几个单位
    - f 表示 format，在前面写了
    - u 表示单位：b 一字节、h 两字节、w 四字节、g 八字节
- `(gdb) info register` 查看所有寄存器 (i r)
- `(gdb) info register <register>` 查看某一寄存器


## gdb 插件
### gdb-peda
每条指令带寄存器、汇编、内存数据回显
```shell
$ git clone https://github.com/longld/peda.git ~/peda
$ echo "source ~/peda/peda.py" >> ~/.gdbinit
```