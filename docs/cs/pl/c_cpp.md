---
counter: True
---

# C/C++

!!! abstract 
    记录一些第一次见过的用法、有用的文章/工具，以及容易忘的知识点

    - 浙江大学 “程序设计与算法基础”（大一秋冬）课程复习笔记


## 程序设计与算法基础

### 考试易错题

- [zjj大佬整理的程算易错题](https://curl.blog.luogu.org/pta-c-yu-yan-li-lun-ti-zheng-li-20209-20211-post)

### 运算符优先级

|优先级|运算符|结合律|
|:--:|:--:|:--:|
|1|后缀运算符：[]  ()  ·  ->|从左到右|
|2|一元运算符：++  --  !  ~  +（正）  -（负）  *  &  sizeof 类型转换|从右到左|
|3|乘除法运算符：*  /  %|从左到右|
|4|加减法运算符：+  -|从左到右|
|5|移位运算符：<<  >>|从左到右|
|6|关系运算符：<  <=  >  >=|从左到右|
|7|相等运算符：==  !=|从左到右|
|8|位运算符 AND：&|从左到右|
|9|位运算符 XOR：^|从左到右|
|10|位运算符 OR：\||从左到右|
|11|逻辑运算符 AND：&&|从左到右|
|12|逻辑运算符 OR：\|\||从左到右|
|13|条件运算符：?:|从右到左|
|14|赋值运算符：=  +=  -=  *=  /=  %=  &=  ^=  \|=  <<=  >>=|从右到左|
|15|逗号运算符：，|从左到右|

### 易忘算法

```cpp title="gcd"
int gcd(int a, int b) {
    return b == 0 ? a : gcd(b, a % b);
}
```

```cpp title="exgcd"
void exgcd(int a, int b, int* d, int* x, int* y) {
    if (!b) { *d = a; *x = 1; *y = 0; }
    else { exgcd(b, a % b, d, y, x); *y -= *x * (a / b); }
}
```

```cpp title="快速幂"
int pow_mod(int a, int p, int n){
    long long res = 1;
    while (p) {
        if (p & 1) res = 1LL * res * a % n;
        a = 1LL * a * a % n;
        p >>= 1;
    }
    return (int)res;
}
```

### 输出类型

别的语言（比如 Python、Haskell）很多都可以通过内置的方法轻松得到一个变量的类型，但是 C/C++ 的话从来没了解过（C 到目前也没了解过内置的有这种功能的库）

查到了 C++ 可以使用 typeid(...).name() 的方法（在头文件 <typeinfo\> 中）得到一个变量的类型，但是结果比较抽象

C++ 还可以使用头文件 <cxxabi.h\> 这个库里提供的 abi::__cxa_demangle 函数来得到类型的字符串，比如：
```cpp
#include <stdio.h>
#include <cxxabi.h>
#include <typeinfo>

int main() {
  int *(*p)[10];
  char* str = abi::__cxa_demangle(typeid(p).name(), NULL, NULL, NULL);
  printf("%s\n", str); // 得到 int* (*) [10]
  return 0;
}
```

又搜索到了 https://cdecl.org/ 这个网站。强的很，直接输入类型声明就可以转换得到英文描述，也可以给英文描述转换成类型声明

源码：[:material-github: ridiculousfish/cdecl-blocks](https://github.com/ridiculousfish/cdecl-blocks)