---
counter: True
comment: True
---

# Esolang 深奥编程语言 

> An esoteric programming language, or esolang, is a computer programming language designed to experiment with weird ideas, to be hard to program in, or as a joke, rather than for practical use.
> <div style="text-align: right">———— esolang wiki</div>

!!! abstract 
    此处整理了一些特殊的编程语言或者正常编程语言的特殊使用方法，多见于Misc题中，但是此页面也仅是介绍一些常见的 Esolang和已经遇到过的Esolang，题目中遇到还是要随机应变，善用搜索
    
    [Esolang, the esoteric programming languages wiki](https://esolangs.org/wiki/Main_Page)

## 极小语言

极小语言指的是指令数很少的一种 Esolang

### BrainFuck

特征：包含 `><+-.,[]` 八个指令，具有图灵完备性

|指令|含义|
|---|---|
| > | 指针加一（右移一位） |
| < | 指针减一（左移一位） |
| + | 指针指向的单元的值加一 |
| - | 指针指向的单元的值减一 |
| . | 输出指针指向的单元内容（ASCII码） |
| , | 输入内容到指针指向的单元（ASCII码） |
| [ | 如果指针指向的单元值为零，向后跳转到对应的 ] 指令的次一指令处 |
| ] | 如果指针指向的单元值不为零，向前跳转到对应的 [ 指令的次一指令处 |
| 其它 | 直接忽略 |

e.g. `++++++++ [>++++++++++++>+++++++++++++<<-] >++++. -. >+++++++. <+. +.`

??? note "BrainFuck 解释器"    
    ```python
    import sys
    
    def Brainfuck(code):
        code = ''.join(filter(lambda x: x in ['.', ',', '[', ']', '<', '>', '+', '-'], code))
        bracemap = buildbracemap(code)
    
        cells, codeptr, cellptr = [0], 0, 0
        result = ''
    
        while codeptr < len(code):
            command = code[codeptr]
            if command == ">":
                cellptr += 1
                if cellptr == len(cells): cells.append(0)
            elif command == "<": cellptr = 0 if cellptr <= 0 else cellptr - 1
            elif command == "+": cells[cellptr] = cells[cellptr] + 1 if cells[cellptr] < 255 else 0
            elif command == "-": cells[cellptr] = cells[cellptr] - 1 if cells[cellptr] > 0 else 255
            elif command == "[" and cells[cellptr] == 0: codeptr = bracemap[codeptr]
            elif command == "]" and cells[cellptr] != 0: codeptr = bracemap[codeptr]
            elif command == ".": result += chr(cells[cellptr])
            elif command == ",": cells[cellptr] = ord(input("[*] input one char > "))
            codeptr += 1
        
        print(f"[+] Result: {result}")
    
    def buildbracemap(code):
        temp_bracestack, bracemap = [], {}
        for position, command in enumerate(code):
            if command == "[": temp_bracestack.append(position)
            if command == "]":
                start = temp_bracestack.pop()
                bracemap[start] = position
                bracemap[position] = start
        return bracemap
    
    if __name__ == "__main__":
        code = input("[*] Input brainfuck code > ")
        Brainfuck(code)
    ```

- 可视化执行：[http://fatiherikli.github.io/brainfuck-visualizer/](http://fatiherikli.github.io/brainfuck-visualizer/)
- [Brainfuck Language - Online Decoder, Translator, Interpreter (dcode.fr)](https://www.dcode.fr/brainfuck-language)
- [Marcos Minond](https://minond.xyz/brainfuck/)

另有众多变种，如 Ook!，Brainfuck+3，*brainfuck 等

要比较注意的一点是，有的 brainfuck 代码会向左越界，这种情况下要把解释器的初始位置往后移一下（比如下面的代码中预先扩充 `cells`，然后令起始的 `cellptr` 大于0）

### Ook!

特征：全是 Ook

[Ook! Programming Language - Esoteric Code Decoder, Encoder, Translator (dcode.fr)](https://www.dcode.fr/ook-language)

## 图形化语言

图形化语言是用一些像素图构建极小语言的 Esolang，最为著名的是 Piet

### Piet

特征：像素图，且只有20种颜色：

```
#FFC0C0 #FFFFC0 #C0FFC0 #C0FFFF #C0C0FF #FFC0FF
#FF0000 #FFFF00 #00FF00 #00FFFF #0000FF #FF00FF
#C00000 #C0C000 #00C000 #00C0C0 #0000C0 #C000C0
#FFFFFF #000000 
```

仅由 `00、C0、FF` 构成，例如：

![hi.png](/assets/images/ctf/esolang/hi.png)

- [DM's Esoteric Programming Languages - Piet (dangermouse.net)](https://www.dangermouse.net/esoteric/piet.html)

- [DM's Esoteric Programming Languages - Piet Samples (dangermouse.net)](https://www.dangermouse.net/esoteric/piet/tools.html)

另还有一些些变种，如 Piet-Q

### Brainloller

特征：像素图，且只有10种颜色，其中8种对应 BF 的8个指令，2种对应指针旋转指令，且仅由 `00、80、FF`构成

|颜色|hex 值|rgb 值|含义|
| --- | --- | --- | --- |
| 红 | #FF0000 | (255, 0, 0) | > |
| 深红 | #800000 | (128, 0, 0) | < |
| 绿 | #00FF00 | (0, 255, 0) | + |
| 深绿 | #008000 | (0, 128, 0) | - |
| 蓝 | #0000FF | (0, 0, 255) | . |
| 深蓝 | #000080 | (0, 0, 128) | , |
| 黄 | #FFFF00 | (255, 255, 0) | [ |
| 深黄 | #808000 | (128, 128, 0) | ] |
| 青 | #00FFFF | (0, 255, 255) | IP顺时针90° |
| 深青 | #008080 | (0, 128, 128) | IP逆时针90° |

例题：第四届”安洵杯”网络安全挑战赛 [CyzCC_loves_LOL](../writeups/d0g3/#cyzcc_loves_lol) 

- [Marcos Minond](https://minond.xyz/brainloller/)

??? note "Brainloller 解释器"
    ```python
    from PIL import Image 
    import sys
    
    def Brainloller(filename):
        source = Image.open(filename).convert("RGB")
        width, height = source.size
        result = ''
        ptr = (0, 0)
        direction = 0
        while True:
            if ptr[0] >= height or ptr[0] < 0 or ptr[1] >= width or ptr[1] < 0:
                break
            else:
                color = source.getpixel((ptr[1], ptr[0]))
                if   color == (255,   0,   0): result += '>'
                elif color == (128,   0,   0): result += '<'
                elif color == (  0, 255,   0): result += '+'
                elif color == (  0, 128,   0): result += '-'
                elif color == (  0,   0, 255): result += '.'
                elif color == (  0,   0, 128): result += ','
                elif color == (255, 255,   0): result += '['
                elif color == (128, 128,   0): result += ']'
                elif color == (  0, 255, 255): direction = (direction + 1) % 4
                elif color == (  0, 128, 128): direction = (direction - 1) % 4
                else: print(f"[-] Unknown color: {color}")
            if   direction == 0: ptr = ptr[0], ptr[1] + 1
            elif direction == 1: ptr = ptr[0] + 1, ptr[1]
            elif direction == 2: ptr = ptr[0], ptr[1] - 1
            elif direction == 3: ptr = ptr[0] - 1, ptr[1]
    
        print(f"[+] BrainFuck Code: {result}")
        return result
    
    def Brainfuck(code):
        code = ''.join(filter(lambda x: x in ['.', ',', '[', ']', '<', '>', '+', '-'], code))
        bracemap = buildbracemap(code)
    
        cells, codeptr, cellptr = [0], 0, 0
        result = ''
    
        while codeptr < len(code):
            command = code[codeptr]
            if command == ">":
                cellptr += 1
                if cellptr == len(cells): cells.append(0)
            elif command == "<": cellptr = 0 if cellptr <= 0 else cellptr - 1
            elif command == "+": cells[cellptr] = cells[cellptr] + 1 if cells[cellptr] < 255 else 0
            elif command == "-": cells[cellptr] = cells[cellptr] - 1 if cells[cellptr] > 0 else 255
            elif command == "[" and cells[cellptr] == 0: codeptr = bracemap[codeptr]
            elif command == "]" and cells[cellptr] != 0: codeptr = bracemap[codeptr]
            elif command == ".": result += chr(cells[cellptr])
            elif command == ",": cells[cellptr] = ord(input("[*] input one char > "))
            codeptr += 1
        
        print(f"[+] Result: {result}")
    
    def buildbracemap(code):
        temp_bracestack, bracemap = [], {}
        for position, command in enumerate(code):
            if command == "[": temp_bracestack.append(position)
            if command == "]":
                start = temp_bracestack.pop()
                bracemap[start] = position
                bracemap[position] = start
        return bracemap
    
    if __name__ == "__main__":
        Brainfuck(Brainloller(sys.argv[1]))
    ```
    

## 特殊关键字语言
### LOLcode

例题：第四届”安洵杯”网络安全挑战赛 [CyzCC_loves_LOL](../writeups/d0g3/#cyzcc_loves_lol) 

[LOLCODE Language - Compiler - Online Decoder, Encoder, Translator](https://www.dcode.fr/lolcode-language)
