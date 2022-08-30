---
counter: True
comment: True
fold_toc: True
---

# Rust 语法基础

!!! abstract
    基础语法，第二遍学的时候做了点笔记

    参考：

    - Rust 圣经，[course.rs](https://course.rs/)
    - The Rust Programming Language，https://doc.rust-lang.org/book/

## 变量
### 标识符命名
- 原生标识符（raw identifiers）
    - 关键字不能作为标识符名称
    - 加上 `#!rust r#` 前缀后可以使用，比如 `#!rust r#match`
- 命名规范：

|类型|惯例方式|
|:--|:--|
|模块 Modules|`snake_case`|
|类型 Types|`UpperCamelCase`|
|特征 Traits|`UpperCamelCase`|
|枚举 Enumerations|`UpperCamelCase`|
|结构体 Structs|`UpperCamelCase`|
|函数 Functions|`snake_case`|
|方法 Methods|`snake_case`|
|通用构造器 General constructors|`new` or `with_more_details`|
|转换构造器 Conversion constructors|`from_some_other_type`|
|宏 Macros|`snake_case!`|
|局部变量 Local variables|`snake_case`|
|静态类型 Statics|`SCREAMING_SNAKE_CASE`|
|常量 Constants|`SCREAMING_SNAKE_CASE`|
|类型参数 Type parameters|`UpperCamelCase`，通常使用一个大写字母: T|
|生命周期 Lifetimes|通常使用小写字母: 'a，'de，'src|

### 变量绑定与可变性
rust 使用 let 关键字来进行变量绑定，即 `#!rust let a = 1;`

而 rust 的变量默认是不可变（immutable）的，使之变成可变的需要在 let 后面加上 mut，如果后面不会改变的变量被声明为了 mutable 的，编译器会给出警告

存在没有使用的变量的话编译器也会给出警告，在变量名前加上单下划线即可忽略

### 变量解构
类似于 python 的元素解包
```rust
let (a, mut b): (bool, bool) = (true, false);
let (a, b, c, d);
(a, b) = (1, 2);
[c, .., d, _] = [1, 2, 3, 4, 5]; // c = 1, d = 4
```

### 常量
常量使用 const 关键字来定义，且必须指定类型，命名通常为蛇形全大写，const 后面也不允许使用 mut，可以在任意作用域内声明
```rust
const MAX_VALUE: u32 = 100_000;
```

### 变量遮蔽
rust 中可以重复声明同一名称的变量，这会再次分配内存，并完全遮蔽掉前面的同名变量

## 基本类型
### 整型
i*长度*（有符号）、u*长度*（无符号）

- i8、i16、i32、i64、i128、u8、u16、u32、u64、u128
- isize、usize 长度由 CPU 决定，32 位 CPU 则是 32 位，64 位 CPU 则是 64 位
- 整型字面量中间可以插入 _
- 字面量结尾可以接类型，例如 `#!rust 10i32, 10_i32`
- 字面量，十六进制 0x...、八进制 0o...、二进制 0b...、字节（仅 u8）b'A'
- 整型默认使用 i32 类型
- 使用 as 来转换类型，例如 `#!rust let a: u16 = 1_u8 as u16;`

debug 模式编译时产生溢出会 panic，而在 release 模式下则不会 panic，按照补码循环溢出。但不能依赖这种行为，想要这样的效果应该标准库的一些方法：

- wrapping_*\** 方法，按照补码循环溢出，例如 `#!rust a.wrapping_add(1)`
- checked_*\** 方法，如果产生溢出了，则会返回 None
- overflowing_*\** 方法，返回结果以及指示是否溢出的布尔值
- saturating_*\** 方法，如果会溢出则保持在最大/最小值上

#### 布尔类型
类型名为 bool，值为 true 或 false，占用 1 字节内存

### 浮点型

- f32 单精度浮点型、f64 双精度浮点型，默认情况下为 f64
- 应该避免判断浮点数相等
- 可以使用 .is_nan() 方法来判断一个数值是否是 NaN
- 数值上也可以使用方法，比如 `#!rust 3.14_f32.round()`

### 运算

- `+ - * / %`：加减乘除取模
- `& | ^ ! << >>`：位运算
- 同样类型才能进行计算、类型转换必须是显式的
- 其它运算可以通过方法实现，.pow() 计算指数，.log() 取对数、.div_euclid() 整除、.div_floor() 等等

### 序列
在 for 循环中常用，用来生成连续的数值，仅可以使用整数、字符等连续的类型，例如：

```rust
for i in 1..5 {
    ...; // i = 1, 2, 3, 4
}
for j in 'a'..='d' {
    ...; // i = 'a', 'b', 'c', 'd'
}
```

### 字符类型
rust 中的字符类型是 char，字面量写法为单引号（双引号表示字符串）

- 一个 char 占四个字节（而不是 C/C++ 中的一个字节）
- 所有 unicode 码元都是一个字符
- 直接存储 unicode 值（即 UCS-4），而不使用 UTF-8 编码

### 单元类型

- 单元类型就是 ()，唯一的值也是 ()，不占内存
- main 函数返回的就是单元类型 ()

### 语句与表达式

- 简单理解就是，带分号的是一个语句，不带分号的是一个表达式，能返回值的就是表达式
- 表达式可以是语句的一部分，比如 `#!rust let a = 1;` 中 1 就是一个表达式，而整体是一个语句
- 函数调用是表达式，因为会有返回值，即使“无”返回值也会返回单元类型
- 用大括号包裹的返回一个值的语句块也是表达式：
    ```rust
    let a = {
        let b = 1;
        b + 1
    };
    ```

### 函数

```rust
fn add(i: i32, j: i32) -> i32 {
    i + j  // 不带分号，返回值；带分号了会返回 ()
}
```

- 定义函数使用关键字 fn
- 函数名、参数名使用蛇形命名
- 必须显式指定参数类型，除了返回 () 外要显式指定返回值类型
- 中途返回使用 return 关键字（带不带分号均可）
- 永不返回的函数类型为 !（相当于 python 类型标注中的 NoReturn），一般用于一定会抛出 panic 的函数或者无限循环：
    ```rust
    fn dead_end() -> ! {
        panic!("...");
    }
    fn forever() -> ! {
        loop { /*...*/ };
    }
    ```

## 所有权与借用
### 所有权

1. Rust 中每一个值都被一个变量所拥有，该变量被称为值的所有者
2. 一个值同时只能被一个变量所拥有，或者说一个值只能拥有一个所有者
3. 当所有者（变量）离开作用域范围时，这个值将被丢弃（drop）

其中作用域的概念和其他语言类似

#### String 类型
`#!rust let s = "abc"` 中 s 的类型为 `#!rust &str`，并不是 String，"abc" 是被硬编码的不可变的字面量。存储的时候是一个指针和字符串长度

而 String 则是通过堆来动态分配内存。比如 `#!rust let s = String::from("abc")`，调用 String 的 from 方法来创建一个 String

如果 s 是 mut 的，则可以通过 `#!rust s.push_str("...")` 来追加字面量

#### 所有权转移
```rust
let x = 1;
let y = x;
```
因为 i32 存储在栈上，所以可以直接拷贝，x 和 y 都为 1，但
```rust
let x = String::from("abc");
let y = x;
```
String 存储在堆上，为 y 赋值本应拷贝地址作浅复制，但这样同一个 String 就有了两个所有者（x 和 y），这是所有权规则不允许的。因此这时 x 会失效，也就是将 String 的所有权转移给 y，后面无法再使用 x 变量。这种操作叫做移动（move）而非拷贝
```rust
let x: &str = "abc";
let y = x;
```
这种情况，因为使用的是 &str 而不是 String，所以 x 仅引用了存储在内存中的字符串，并不对它持有所有权，因此 `#!rust let y = x` 时对存在栈上的引用进行了拷贝，而不需要移动。所以这之后 x 和 y 均可用

- rust 永远不会自动创建数据的深拷贝
- 使用 .clone() 可以深拷贝存在堆上的数据，但性能降低
    ```rust
    let x = String::from("abc");
    let y = x.clone(); // 后面 x、y 均可用，因为是所有的是不同数据
    ```

#### 函数传值与返回
向函数中传值也会发生移动或者复制
```rust
fn main() {
    let s = String::from("abc");
    print(s);
    // 这里 s 将不能使用
}

fn print(string: String) {
    println!("{}", string); // s 的所有权到这里
} // string 被释放
```
从上面的例子可以看出，s 对于 String 的所有权在函数传值调用时被移动给了 print 函数的 string 变量。然后随着 print 函数的结束，string 作用域结束，这个值内存被 drop。并且由于在调用时 s 被移动了，所以在调用后 s 将不能被使用。若想在调用后继续使用 s，一种方法是将 s.clone() 传给 print，另一种方法则是利用返回：
```rust
fn main() {
    let mut s = String::from("abc");
    s = print(s);
    println!("{}", s); // 这里 s 可用
}

fn print(string: String) -> String {
    println!("{}", string);
    string
}
```
函数在返回的时候也会移动所有权，比如上面例子中，print 函数结束后，将 string 移动了出去，赋值给了 s，这时 s 就拿到了返回值的所有权，后面仍可以继续使用。但这要求 s 是 mut 的（因为发生了变化），或者使用变量遮蔽（`#!rust let s = print(s)`）

### 引用与借用
rust 中也有引用的概念，获取一个变量的引用也称为借用（borrowing），使用 & 来进行引用，\* 来解引用：
```rust
let x: i32 = 1;
let y: &i32 = &x; // 引用类型
assert_eq!(x, *y);
```
也可以通过借用来进行函数调用，从而维持参数的所有权：
```rust
fn main() {
    let s = String::from("abc");
    let len = func(&s);    // 创建 s 的引用，并传入
    println!("{} {}", s, len); // s 仍可用
}

fn func(string: &String) -> usize { // 接收引用
    string.len()  // 直接调用方法
} // string 离开作用域，但它并不拥有任何值，所以不会发生什么
```
但是此时的引用是不可变引用，也就是说，不能在 func 函数中进行 `#!rust string.push_str("...")`

使用 &mut 可以创建可变引用，例如：
```rust
let mut x: i32 = 1;
let y: &mut i32 = &mut x;
```
```rust
fn main() {
    let mut s = String::from("abc");
    func(&mut s); // 创建 s 的可变引用
    println!("{}", s) // 输出 abc...
}

fn func(string: &mut String) { // 接收可变引用
    string.push_str("...")  // 可以进行更改
}
```
但是对于可变引用，rust 有一些限制：

- 在同一个作用域内，一个数据只能有一个可变引用
- 可变引用和不可变引用不能同时存在

这样做的目的是避免产生数据竞争，以及防止不可变引用的值被可变引用所改变

以及如果存在引用，且后面用到了这个引用，则被引用的即使是 mut 的，也不能被修改，例如：
```rust
fn main() {
    let mut x = 1;
    let y = &x; //borrow later used here
    println!("{}, {}", x, *y);
    x = 2; // assignment to borrowed `x` occurs here
    println!("{}, {}", x, *y); // borrow later used here
}
```
则会产生如上注释中的错误，而如果在 `#!rust x = 2` 后面没有再用到 y，则是可以通过编译正常更改 x 的

以及如下代码也会编译错误：
```rust
fn main() {
    let mut x = 1;
    let y = &mut x;
    println!("{}, {}", x, *y); // cannot borrow `x` as immutable because it is also borrowed as mutable
}
```
因为在传入宏时，实际上对 x 进行了借用，因此同时存在了可变和不可变的引用，导致报错

#### 避免悬垂引用
悬垂引用（dangling references）也称悬垂指针，意思是指针指向的值被释放掉了，导致指针指的位置不存在期望的内容。rust 不会允许这种情况发生，比如
```rust
fn dangle() -> &String {
    let s = String::from("abc");
    &s
}
```
这里返回了 s 的引用，但是在函数结束后 s 离开了作用域，被释放掉了，所以返回的其实是悬垂引用，rust 编译器将不会通过

## 复合类型
### 字符串
- &str 与 String 是两个不同的类型
- 可以使用 &s[a..b] 的方式来获取切片的引用，切片使用的是前面的 range 类型，语法和 python 的切片类似，同样可以省略头尾
    - 对一个 String 使用切片获得的引用类型也是 &str
    - 切片是按字节进行的，需要精确切到字符边界。例如对中文字符串进行切片，&s[0..3] 会切出一个汉字字符，而 &s[0..2] 没切完整会导致 panic
- 字符是 UCS-4 编码，字符串是 UTF-8 编码（每个字符字节数不定）
- String 与 &str 转换
    - &str -> String
        - String::from("...")
        - "...".to_string()
    - String -> &str
        - &s / &s[..]
        - s.as_str()
- String 操作
    - .push('a') 追加字符 / .push_str("...") 追加字符串
    - .insert(n, 'a') 在索引 n 的位置插入字符 / .insert(n, "...") 同理插入字符串
    - .replace("aaa", "AAA") 全局替换所有 "aaa" 到 "AAA"，返回替换后的新字符串，原字符串不变
    - .replacen("aaa", "AAA") 同上，但只替换 n 次
    - .replace_range(a..b, "...") 将索引 a..b 的范围替换为新字符串 "..."，直接操作原字符串
    - .pop() 删除并返回最后一个字符，返回值为一个 Option，若字符串为空则返回 None
    - .remove(n) 删除以索引 n 开头的一个字符
    - .truncate(n) 删除索引 n 开头及之后的所有字符
    - .clear() 清空字符串
    - 使用 + 或 += 连接一个 &str 字符串（不能是 String）
        - \+ 运算符左侧的变量将失效，因为所有权转移到了 .add() 方法中然后被释放
    - 可以使用 `let s = format!("{} {}", s1, s2)` 来连接创建新的字符串
- 字符串转义
    - "\x.." 十六进制表示，必须在 \x00 到 \x7f 之间
    - "\u{....}" 用 codepoint 表示一个 unicode 字符
    - 可以直接换行，但从下一行行首开始就记录文本（也就是不当作缩进忽略），行尾加 \ 不换行，且下一行行首空格忽略
    - 其它转义和其它语言均类似
    - r"..." 中的 \ 不参与转义（和 python 类似）
    - r#"..."# 中的双引号不会提前结束字符串（也就相当于不需要转义双引号）
    - r##"..."## 中的 "# 也不会提前结束字符串（双引号前后的井号加多少都可以，只需要匹配即可）
- 操作 UTF-8 字符串
    - 循环遍历字符可以使用 `#!rust for c in "...".chars()`
    - 循环遍历字节可以使用 `#!rust for c in "...".bytes()`
    - 其它操作标准库中没有，需要通过别的 crates

### 元组
- 长度固定，元素顺序及类型固定的复合类型，例如 `#!rust let t: (i32, f64) = (1, 1.1);`
- 使用模式匹配获取元组中的值：`#!rust let (a, b) = t;`
- 使用 . 来访问元组内容：`t.0 == 1`

### 结构体
使用 struct 关键字来定义结构体，指明字段名与类型：
```rust
struct User {
    name: String,
    age: u32,
    email: String,
}
```
创建结构体实例时每个字段都需要初始化，且顺序可以打乱：
``` rust
let user1 = User {
    age: 19_u32,
    name: String::from("TonyCrane"),
    email: String::from("tonycrane@foxmail.com"),
};
```
访问结构体字段直接使用 . 就可以。修改某一字段需要将整个结构体标记为 mut，无法将某一字段单独标记为 mut

另外，在结构体中使用引用类型需要用到生命周期

#### 简化创建
```rust
fn build_user(name: String, age: u32) -> User {
    User {
        name,  // name: name 缩写
        age,   // age: age 缩写
        email: String::from(""),
    }
}
```
当参数名和字段名相同的时候可以省略掉内容

#### 更新结构体
通过已有结构体实例创建新实例：
```rust
let user2 = User {
    email: String::from("another@example.com"),
    ..user1 // 必须写在后面
};
```
将 user1 除了 email 之外的字段**移动**到 user2 中。因为这是移动，所以发生了所有权的转移，导致 user1.name 后面不能被使用。但因为 u32 实现了 Copy trait，所以 user1.age 仍可以使用。并且 user1.email 所有权并没有转移，仍然可以使用

#### 元组结构体
可以定义像元组一样没有字段名的结构体：
```rust
struct Point(i32, i32, i32);
let point = Point(0, 0, 0);
```

#### 单元结构体
像单元类型一样，没有任何字段和属性的结构体。作用上来看就是不关心数据，但关心行为（后面 impl 之类的）
```rust
struct UnitLikeStruct;
let a = UnitLikeStruct;
```

#### 打印结构体
结构体不能直接被放在 {} 中打印，因为没有实现 Display trait

一种方便的输出方式是利用 `#!rust #[derive(Debug)]` 来自动实现 Debug trait 来利用 {:?} 格式化或 dbg! 宏进行 debug 打印：
```rust
#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}

fn main() {
    let rect = Rectangle { width: 30, height: 50 };
    println!("{:?}", rect);
    dbg!(rect); // 输出到 stderr 流中
}
```
输出为：
```text
Rectangle { width: 30, height: 50 }
[src/main.rs:10] rect = Rectangle {
    width: 30,
    height: 50,
}
```

### 枚举
使用 enum 关键字来定义枚举类型，用 :: 来访问成员，可以包含值：
```rust
enum Message {
    Quit,
    Move { x: i32, y: i32 },
    Write(String),
    ChangeColor(i32, i32, i32),
}

fn main() {
    let m1 = Message::Quit;
    let m2 = Message::Move{ x: 1, y: 1 };
    let m3 = Message::ChangeColor(255, 255, 0);
}
```

#### Option
类似 Haskell 中的 Maybe，定义是：
```rust
enum Option<T> {
    Some(T),
    None,
}
```
使用时无需添加 Option:: 前缀，提取值可以使用模式匹配

### 数组
- rust 中数组长度固定，必须有相同类型，存储线性排列在栈上，速度快
- 一个数组的类型是 [*元素类型*; *元素个数*]，例如 `#!rust [i32; 5]` 表示包含 5 个 i32 的数组
- 使用同一个重复元素初始化数组，例 `#!rust let a = [3; 5]` 即 a 为包含 5 个 3 的数组
- 索引使用 []，与其它语言相同
- 越界访问会触发 panic
- 和字符串一样可以创建切片引用

## 流程控制
### 分支
- if - else if - else 结构
- 条件不需要加括号
- if 语句块是表达式，可以用来赋值

### 循环
- for 循环
    - for ... in ... 结构
    - in 后面的集合一般需要使用引用，否则会将所有权移至 for 块内（实现了 Copy trait 的除外）
    - 循环中修改元素的话一般需要使用可变引用
    - 带索引循环
        ```rust
        let a = [4, 3, 2, 1];
        for (i, v) in a.iter().enumerate() {
            // ...
        }
        ```
    - 仅循环多少次：`#!rust for _ in 0..10` 循环 10 次
    - 可以使用 continue 和 break 控制循环
- while 循环
    - 没什么特别的
- loop 循环
    - 不会自动停止，需要靠 break
    - 是一个表达式，可以利用 break 来返回一个值
        ```rust
        let result = loop {
            cnt += 1;
            if cnt == 10 {
                break cnt * 2;
            }
        };
        ```

rust 中可以使用 label 来指定多重循环中 break 或 continue 哪一层循环：
```rust
'outer: for i in 0..10 {
    println!("Outer: #i = {}", i);
    'inner: for j in 0..10 {
        println!("Inner: #j = {}", j);
        if j == i { continue 'outer; }
        if i == 5 { break 'outer; }
        if j != 0 { continue 'inner; }
        println!("...");
    }
}
```

## 模式匹配
rust 中有很多模式匹配，比如 let 语句、for 循环本身就相当于模式匹配：
```rust
let (x, y) = (1, 2);
for (index, value) in v.iter().enumerate() { /* ... */ }
```
以及函数参数：
```rust
fn func(&(x, y): &(i32, i32)) {
    // x 和 y 会从这一个参数中匹配出来
}
```
除此之外还有一些专门利用模式匹配的语法：

### match 语句
类似 python 的 match-case 语句，以及 Haskell 的模式匹配以及守卫语法
```rust
match target {
    pattern1 => expression1,
    pattern2 => {
        statements1;
        statements2;
        expression2
    },
    pattern3 | pattern4 => expression3,
    _ => expression4,
}
```

- 整个 match 语句块是一个表达式
- match 必须穷举出所有模式，未列出的剩余部分使用通配符 _ 表示其它所有可能性
    - _ 不会被绑定，可以多次使用，其匹配到的值都会被忽略
- match 的每一个分支都必须是一个表达式，且所有分支的表达式返回值类型需要相同
- | 表示或，即匹配二者中的一个即可
- 可以利用模式匹配来绑定新变量
- 序列也可以作为模式，比如 x = 5 就可以匹配模式 1..=5
- 可以使用 .. 来忽略剩余值
    ```rust
    let origin = Point { x: 0, y: 0, z: 0 };
    match origin {
        Point { x, .. } => println!("x is {}", x),
    }
    let numbers = (2, 4, 8, 16, 32);
    match numbers {
        (first, .., last) => println!("Some numbers: {}, {}", first, last),
    }
    ```
- 可以在模式后面增加额外的 if 条件，称为匹配守卫（match guard）
    ```rust
    let num = Some(4);
    match num {
        Some(x) if x >= 0 & x < 5 => println!("less than five: {}", x),
        Some(x) => println!("{}", x),
        None => (),
    }
    ```
    - 在有 | 的情况下，if 语句的条件会作用于所有的模式，而不是最后一个
- 可以使用 @ 来为字段绑定变量，比如上面的例子里第一个匹配可以写为 `#!rust Some(x @ 0..5)`
    - Rust 1.53 新语法：如 `#!rust num @ (1 | 2) => ...` 将 1 或 2 绑定到 num 变量上
    - Rust 1.56 新语法：和 Haskell 中 @ 用法类似，在解构的同时保留原值，如
        ```rust
        let p @ Point {x: px, y: py} = Point {x: 10, y: 20};
        // p = Point {x: 10, y: 20}, px = 10, py = 20
        ```

### if let / while let
只需要匹配一个模式、忽略其它模式时，可以使用 if let 语句来简化，比如下面代码
```rust
let v = Some(1);
match v {
    Some(1) => println!("!"),
    _ => (),
}
```
可以写为
```rust
let v = Some(1);
if let Some(1) = v { // 是一个等号，不是双等号
    println!("!");
}
```
与之相似的是 while let 语句，只要匹配就一直进行循环，例如：
```rust
let mut stack = Vec::new();
// ...
while let Some(top) = stack.pop() {
    println!("pop {}", top);
}
```

### matches! 宏
仅仅需要判断一个值是否和一个模式匹配的话可以使用 matches! 宏：
```rust
matches!(value, pattern)
```
如果匹配则返回 true，否则返回 false

## 方法
Rust 中使用 impl 块来为结构体定义方法，可以当作，struct 定义“类”的属性，impl 块中定义“类”的方法
```rust
impl StructName {
    fn new(...) -> StructName {
        StructName {
            ...
        }
    }
    fn method(&self, ...) -> ... {
        ...
    }
}
```

- 一个方法的第一个参数为 self 等，表示自身，且服从所有权规则
    - self：将调用者的所有权转移到方法中，少用（类型为 `#!rust Self`，表示结构体自身类型）
    - &self：在方法中使用调用者的不可变借用，常用（实际上是 `#!rust self: &Self` 的语法糖）
    - &mut self：在方法中使用调用者的可变借用，常用
- 方法名可以与字段名相同（一般用来实现 getter）
- rust 会为 &self 等自动引用与解引用
- impl 块中没有 self 参数的函数称为关联函数（如上面的 new）
    - 不能使用 . 来以方法的形式调用
    - 应该使用 :: 来调用（相当于调用这个结构体命名空间中的函数）
    - new 一般用来作为构造器，即从参数返回一个结构体
- 可以在多个 impl 块中为同一个结构体定义方法
- impl 也可以为枚举类型定义方法

## 泛型 Generics
```rust
fn add<T: std::ops::Add<Output = T>>(a: T, b: T) -> T {
    a + b         // ^ 保证可以 T 相加并得到 T 类型的结果
}
```

- `#!rust <T>` 为一个函数规定一个泛型 T，冒号后面接需要的 trait 来添加限制
- 可以通识定义多个泛型，用逗号隔开即可
- 结构体、枚举等都可以使用泛型
    ```rust
    struct Point<T> {
        x: T,
        y: T,
    }
    impl<T> Point<T> {
        //... 这里可以使用 T
    }
    enum Option<T> {
        Some(T),
        None,
    }
    ```
- 可以为带泛型的结构体针对某一具体类型实现方法：
    ```rust
    impl Point<f32> {
        // only for Point<f32>
    }
    ```
- 调用泛型函数
    ```rust
    struct SGen<T>(T);
    fn func<T>(arg: SGen<T>) { /* ... */}
    fn main() {
        func(SGen('a'));         // 隐式指定类型参数 T 为 char
        func::<char>(SGen('a')); // 显式指定类型参数 T 为 char
    }
    ```
- const 泛型，定义一个基于值的泛型参数
    ```rust
    fn func<T: ..., const N: usize>(arr: [T; N]) {
        // ...
    }
    ```
    - const 泛型参数只能接受不带其它泛型参数的实参

## 特征 Trait
特征类似于 python 中的抽象基类，规定一些必须有的方法，但差别还是很大

- 定义 trait
    ```rust
    pub trait MyTrait {
        fn func1(&self) -> ...; // 分号结尾，不用写函数内容
        fn func2(&self) -> ... {
            ... // 提供默认实现
        }
    }
    ```
    - pub 关键字使之可以从外部导入
    - trait 块中对于需要实现的方法可以只写签名，也可以将函数写完整来提供一个默认实现
- 为类型实现特征
    ```rust
    impl MyTrait for MyType {
        fn func1(&self) -> ... {
            ...
        }
    }
    ```
    - 孤儿规则：为 A 类型实现特征 T，则 A 和 T 中至少有一个在当前作用域中定义，例如不可以为标准库中的类型实现其它标准库中的特征。确保某一库中的代码不会被在被使用的时候破坏
    - 如果一个特征的方法都有默认实现，则花括号内可以不写任何东西
- 特征约束
    - 参数里直接写特征是泛型的一个语法糖，以下两行代码效果一样
        ```rust
        pub fn func(arg: &impl MyTrait) {}
        pub fn func<T: MyTrait>(arg: &T) {}
        ```
    - 参数里有特征时不会强制所有这样的参数为同一类型，比如以下三行代码 1 和 2 等价、和 3 不等价
        ```rust
        pub fn func(a: &impl MyTrait, b: &impl MyTrait) {}
        pub fn func<T: MyTrait, U: MyTrait>(a: &T, b: &U) {}
        pub fn func<T: MyTrait>(a: &T, b: &T) {}
        ```
    - 多重约束
        ```rust
        pub fn func(arg: &(impl Trait1 + Trait2)) {}
        pub fn func<T: Trait1 + Trait2>(arg: &T) {}
        ```
    - where 约束
        ```rust
        pub fn func<T, U>(t: &T, u: &U) -> ...
            where T: Trait1 + Trait2 + Trait3,
                  U: Trait4 + Trait5 + Trait6
        {}
        ```
    - 函数返回值可以只说实现了某个特征的类型，而不明确规定
        ```rust
        fn func() -> impl MyTrait {}
        ```
- derive 可以派生特征，使用默认实现，如前面写过的 `#!rust #[derive(Debug)]`
    - Debug、PartialEq、Eq、PartialOrd、Ord、Clone、Copy、Hash、Default
    - 多个的话中间逗号分隔
- 调用实现了某一特征的类型的方法时需要先用 use 将特征引入
- 例子
    - 为 Point 实现加法
        ```rust
        use std::ops::Add;
        #[derive(Debug)]
        struct Point<T: Add<T, Output = T>> {
            x: T,
            y: T,
        }
        impl<T: Add<T, Output = T>> Add for Point<T> {
            type Output = Point<T>; // 关联类型
            fn add(self, p: Point<T>) -> Point<T> {
                Point {
                    x: self.x + p.x,
                    y: self.y + p.y,
                }
            }
        }
        ```
    - 为 Point 实现格式化输出
        ```rust
        use std::fmt;
        use std::fmt::Display;
        impl Display for Point {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "({}, {})", self.x, self.y)
            }
        }
        ```

### 特征对象
比如使用一个 Vec 来存储实现同一个特征的不同类型的时候，就需要用到特征对象，例如 `#!rust Vec<Box<dyn MyTrait>>`

- 使用泛型来代替的话，Vec 中的所有值类型必须一致
- 只能使用 & 引用或者使用 Box 智能指针来创建特征对象
    - `&dyn MyTrait` 在用的时候需要用 & 借用
    - `Box<dyn MyTrait>` 在用的时候需要通过 Box::new(...) 来基于某个值创建智能指针
    - 创建的时候不需要加 dyn
    - 不使用这两种方法的话，大小会未知，但 &dyn 和 Box<dyn\>  大小都已知
    - dyn 代表动态分发（dynamic dispatch）
- 特征对象的限制：只有对象安全的特征才能创建特征对象
    - 对象安全：
        - 方法的返回类型不能是 Self
        - 方法没有任何泛型参数
    - Clone 特征的 clone 方法返回的就是 Self，因此它不是对象安全的。`#!rust Box<dyn Clone>` 的写法会报错

### 关联类型
关联类型定义 trait 块中，可以在后续的方法中使用该类型。例如 Iterator 的定义：
```rust
pub trait Iterator {
    type Item;
    fn next(&mut self) -> Option<Self::Item>;
}
```

这种写法比为 Iterator 增加一个泛型更有可读性，而且写起来也简便

### 默认泛型类型参数
例如 Add 这个 trait：
```rust
trait Add<RHS=Self> {
    type Output;
    fn add(self, rhs: RHS) -> Self::Output;
}
```

Add 的 RHS 泛型参数带有一个默认值 Self，也就是说，在 impl 的时候，如果不为 Add 指定类型，则默认 RHS 是 Self，即要加的东西类型和被加的东西类型一致。例如：
```rust
struct Point {
    x: i32,
    y: i32,
}
impl Add for Point { // 默认就是要加 Point
    type Output = Point;
    fn add(self, other: Point) -> Point {
        ...
    }
}
```

### 同名方法调用
当一个类型的方法与它实现的 trait 的方法名重名时，直接调用会调用类型上的方法。想要调用 trait 上的方法时需要使用 :: 来显式调用，如：
```rust
trait A { fn func(&self); }
trait B { fn func(&self); }
struct C;

impl A for C {
    fn func(&self) { println!("A"); }
}
impl B for C {
    fn func(&self) { println!("B"); }
}
impl C {
    fn func(&self) { println!("C"); }
}

fn main() {
    let c = C;
    c.func();       // C
    A::func(&c);    // A
    B::func(&c);    // B
    C::func(&c);    // C 与第一个相同，但显式调用
}
```

这样调用的一个条件是方法的第一个参数是 self（又叫方法接收器 receiver），但如果是关联函数的话，就没有这个 receiver，rust 也就自然不知道是调用哪个类型实现的特征上的方法

这时需要使用完全限定语法：
```rust
<Type as Trait>::function(receiver_if_method, next_arg, ...);
```
例如：
```rust
trait A { fn func(); }
struct B;

impl A for B {
    fn func() { println!("A"); }
}
impl B {
    fn func() { println!("B"); }
}

fn main() {
    B::func();          // B
//  A::func();          // 报错
    <B as A>::func();   // A
}
```

### trait 定义中的 trait 约束
如果在定义特征 A 的时候需要使用特征 B 的方法，则 A 和 B 都要实现（实现了就好，先后无所谓）。在定义 A 的时候就可以在后面加上约束 B：
```rust
trait A: B {
    ...
}
```

### 绕过孤儿规则
绕过孤儿规则，也就是在外部类型上实现外部特征，一种方法是使用 newtype 模式，即创建一个元祖结构体来包装外部类型，这样就构造了一个在当前作用域内的新类型

比如想要为 `#!rust Vec<String>` 实现 Display trait，二者都在标准库中，无法直接实现。使用 newtype 模式：
```rust
use std::fmt;
struct Wrapper(Vec<String>);
impl fmt::Display for Wrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}]", self.0.join(", "))
    }
}

fn main() {
    let w = Wrapper(vec![String::from("abc"), String::from("def")]);
    println!("w = {}", w);
}
```

## 集合类型
### Vector
- 动态数组，类型 Vec<T\>
- 创建
    - 使用 Vec::new() 创建
        - 如果预先知道容量，可以使用 Vec::with_capacity(cap) 创建，会提升性能
    - 使用 vec! 宏来创建，同时给予初值
        ```rust
        let v = vec![1, 2, 3]; // 自动推断类型
        ```
    - 使用 Vec::from(...) 来从数组创建
- Vector 类型在移出作用域后会自动删除，其存储的内容也会被删除
- 操作
    - .push(...) 在末尾添加元素
    - .pop() 剔除末尾元素
    - .extend(...) 扩展
    - .len() 获取长度
    - 可以使用切片来借用元素（越界会 panic）
    - .get(index) 来根据索引访问元素，返回类型是 Option<&T\>（越界返回 None）
    - `#!rust for i in &v` 遍历
    - 利用 enum 或特征对象来存储不同类型的

### HashMap
- 存储键值对，类型 HashMap<K, V\>
- 需要使用 std::collections::HashMap 引入
- key 一定要实现 Hash 和 Eq trait
    - f32 和 f64 不可以
- 创建
    - HashMap::new()
    - HashMap::with_capacity(cap)
    - 使用迭代器和 collect
        ```rust
        let lst = vec![(key1, value1), (key2, value2), ...];
        let map: HashMap<_, _> = lst.into_iter().collect();
        ```
- 操作
    - .insert(key, value) 插入一个键值对
    - .get(key) 获取值，返回 Option<V\> 类型
    - 直接使用 [key] 获取值，没有 key 会 panic
    - .entry(key).or_insert(value)
        - 如果存在 key，则返回 key 对应的值
        - 如果不存在 key，则插入 key-value 键值对
        - 返回一个 &mut V 引用，可以直接修改 map 中内容
    - .contains_key(key) 查询是否存在 key

## 类型转换
- 一般情况下（方法调用除外）Rust 不会进行隐式的类型转换
- 使用 as *type* 进行显式的转换
- 超过最大值会溢出，如 300_i32 as i8 会得到 44，而不会 panic
- 内存地址转换为指针
    ```rust
    let mut values: [i32; 2] = [1, 2];
    let p1: *mut i32 = values.as_mut_ptr();
    let first_address = p1 as usize; // 将 p1 内存地址转换为一个整数
    let second_address = first_address + 4;
    let p2 = second_address as *mut i32; // 访问该地址指向的下一个整数 p2
    unsafe {
        *p2 += 1;
    }
    assert_eq!(values[1], 3);
    ```
- TryInto 转换
    - use std::convert::TryInto，但不必要，在 prelude 中
    - TryInto trait 有 .try_into 方法，返回一个 Result，使用 .unwrap() 提取
        ```rust
        let a: u16 = 1500;
        let b: u8 = b.try_into().unwrap();
        ```
    - 大类型转换为小类型会返回 Err(e)

### 方法调用时的强制类型转换

例如在调用 a.func() 时（a 的类型为 T），编译器会进行以下操作

1. 尝试值方法调用，即 T::func(a)
2. 如果上一步无法完成，则尝试引用方法调用，即
    - <&T\>::func(a)
    - <&mut T\>::func(a)
3. 如果上一步仍然无法完成，则试着解引用 T，如果 T 满足 Deref<Target = U\>，即 T 可以被解引用为 U，则编译器会使用 U 类型尝试调用（从 1 开始同样的步骤），称为解引用方法调用
4. 如果 T 不能被解引用，且 T 是一个定长类型，则编译器会尝试将 T 转为不定长类型（例如 [i32; 2] 转为 [i32]）
5. 如果上面都不行，则不能通过编译

???+ example "例 1"
    ```rust
    let array: Rc<Box<[T; 3]>> = ...;
    let a = array[0]; // 可以获取第一个元素
    ```

    会进行以下步骤：

    1. array[0] 实际上表示 array.index(0)（Index trait）
    2. 检查 array 是否实现 Index 特征，Rc<Box<[T; 3]\>\> 没有实现，尝试不可变引用和可变引用，都没有实现，无法调用
    3. 尝试解引用 array，变为 Box<[T; 3]\> 类型，对其调用 .index(0)
    4. Box<[T; 3]\>、&Box<[T; 3]\>、&mut Box<[T; 3]\> 都没有实现 Index，无法调用
    5. 解引用 Box<[T; 3]\>，得到 [T; 3]
    6. [T; 3] 也没有实现 Index（只有数组切片才可以通过索引访问），引用、解引用都不行
    7. 将定长 [T; 3] 转为不定长 [T]，也就是数组切片，它实现了 Index，可以调用 .index(0) 方法

??? example "例 2"
    已知 clone 方法的签名是 `#!rust fn clone(&T) -> T;`
    ```rust
    fn func<T: Clone>(value: &T) {
        let cloned = value.clone();
    }
    ```
    上述代码中因为 value 本身是 &T 类型，所以可以直接调用 clone 方法得到一个 T 类型的 cloned
    ```rust
    fn func<T>(value: &T) {
        let cloned = value.clone();
    }
    ```
    上述代码虽然没有为 T 限制 Clone 特征，但是仍然可以通过编译。这时无法直接调用 value.clone()，所以会尝试进行引用方法调用，此时 T 变为 &T，&T 实现了 Clone 特征，所以可以调用，但这时 clone 的签名相当于 `#!rust fn clone(&&T) -> &T`，所以最后得到的结果 cloned 的类型为 &T

## 返回值与错误处理
Rust 认为的两种错误：

- 可恢复错误，只影响用户自身的操作，不会对系统产生影响
- 不可恢复错误，全局性或者系统性的错误，对于系统影响很大

Rust 推荐可恢复错误使用 Result<T, E\> 返回值等待后续处理异常，不可恢复错误直接 panic 终端程序

### panic
- 可以通过 panic! 宏来直接抛出一个 panic
- 运行时带有 RUST_BACKTRACE=1 环境变量的话，会显示回溯栈（需要开启 debug 标志）
- panic 时有两种方式来终止：
    - 栈展开：回溯栈上数据和函数调用，可以提供充分报错信息和栈调用信息
    - 直接终止：不清理数据，直接退出程序，交给系统来清理
    - 默认情况是栈展开
    - 直接终止编译出的可执行文件更小，可以在 release 时指定使用直接终止：
        ```toml
        [profile.release]
        panic = 'abort'
        ```
- 如果是 main 线程 panic 了，则程序终止。如果子线程 panic 了，则线程终止，main 线程仍然运行，程序不会结束

### Result
Result 是一个枚举类型，定义为：
```rust
enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

- 使用 match 来处理 Result 类型
    - 例如 IO 错误，可以对于 Err(error) 再匹配 error.kind()，其可能的值在 std\:\:io::ErrorKind 中
    - 可以配合 panic，将 error 用 debug 模式（{:?}）进行输出
- 对于 Result，如果失败就 panic
    - 使用 .unwrap()：如果是 Err 则会 panic，并输出错误内容
    - 使用 .expect("...")：同样 panic，但会显示为 panicked at '...: *Err 内容*'
- `?` 传播错误
    - 在函数中判断 Result，并传递返回 Err 可以写为
        ```rust
        fn func() -> Result<String, io::Error> {
            let f = File::open("test.txt");
            let mut f = match f {
                Ok(file) => file,
                Err(e) => return Err(e),
            };
            let mut s = String::new();
            match f.read_to_string(&mut s) {
                Ok(_) => Ok(s),
                Err(e) => Err(e),
            }
        }
        ```
    - 其中 match-return Err 部分可以利用 ? 来简写：
        ```rust
        let mut f = File.open("test.txt")?;
        ```
    - ? 在返回 Err 的时候会自动转换错误类型，例如：
        ```rust
        fn func() -> Result<File, Box<dyn std::error::Error>> {
            let mut f = File::open("test.txt")?;
            Ok(f)
        }
        ```
        - 在 ? 处理返回错误的时候，得到的是 std\:\:io::Error 类型，? 可以自动调用 From trait 的 from 方法，将 std\:\:io::Error 转为需要的 Box<dyn std::error::Error\>
    - ? 可以进行链式调用：
        ```rust
        fn func() -> Result<String, std::io::Error> {
            let mut s = String::new();
            File::open("test.txt")?.read_to_string(&mut s)?;
            Ok(s)
        }
        ```
        - 对于这个操作，Rust 标准库提供了 std::fs::read_to_string(filename) 函数，而且返回的就是 Result<String, std\:\:io::Error\>
- ? 结合 Option
    - 和 Result 同理，? 也适用于 Option 的返回，也就是得到 None 就立即返回 None，否则展开出 Some 中的值
- main 函数返回值
    - main 函数可以有返回值类型 Result<(), Box<dyn std::error::Error\>\>
    - 只有声明了这种返回值的 main 函数中才可以使用 ? 来提前探测错误终止 main 函数：
        ```rust
        use std::error::Error;
        use std::fs::File;
        fn main() -> Result<(), Box<dyn Error>> {
            let f = File::open("test.txt")?;
            Ok(())
        }
        ```
- try! 宏
    - ? 的早期版本，避免使用
    - 定义：
        ```rust
        macro_rules! try {
            ($e:expr) => (match $e {
                Ok(val) => val,
                Err(err) => return Err(::std::convert::From::from(err)),
            });
        }
        ```
    - 使用方法，以下两行等价：
        ```rust
        let x = func()?;
        let x = try!(func());
        ```

## 包和模块
### crate 与 package
- crate 是一个独立的可编译单元，可以编译出可执行文件或者一个库
- package 是 cargo 创建的包含 Cargo.toml 的“项目”，可以包含因为功能性被组织在一起的一个 crate 或多个 crate
    - 一个 package 只能包含一个库（library）类型的 crate，可以包含多个二进制类型的 crate
    - cargo new 默认创建的就是二进制 package
        - src/main.rs 是二进制 crate 的根文件，其包名和所属 package 相同，入口点在 main 函数
    - cargo new <*name*\> --lib 创建库 package
        - 库 package 只能作为第三方库被引用，不能使用 cargo run 运行
        - src/lib.rs 是库类型同名 crate 的根文件

#### 典型 package 结构
```text
.
├── Cargo.toml
├── Cargo.lock
├── src
│   ├── main.rs    // 默认二进制 crate（编译生成 package 同名可执行文件）
│   ├── lib.rs     // 唯一库 crate
│   └── bin        // 其余二进制 crate（分别生成文件名同名可执行文件）
│       └── main1.rs
│       └── main2.rs
├── tests     // 集成测试
│   └── some_integration_tests.rs
├── benches   // 基准性能测试 benchmark 文件
│   └── simple_bench.rs
└── examples  // 示例
    └── simple_example.rs
```

### 模块 Module
- 在 lib.rs 中使用 mod 关键字创建模块，后接模块名
- mod 可以嵌套，模块中可以定义各种 rust 类型
- src/main.rs 和 src/lib.rs 称为 crate root
- 模块使用 :: 逐级访问
    - crate 指根，使用 crate 也就相当于使用绝对路径
    - super 指父模块（上一级），相当于文件系统中的 ..
    - self 指自身模块

如下 lib.rs：
```rust
mod A {
    mod B {
        fn func_a() {
            self::func_b();
        }
        fn func_b() {
            super::C::func_c();
        }
    }
    mod C {
        fn func_c() {}
    }
}
pub fn func() {
    crate::A::B::func_a(); // 绝对路径引用
    A::B::func_b();        // 相对路径引用
    self::A::C::func_c();  
}
```
它的模块树为：
```text
crate
  ├── func
  └── A
      ├── B
      │   ├── func_a
      │   └── func_b
      └── C
          └── func_c
```

- 仅使用 mod *name*; 将创建一个模块，并从同目录下同名的 *name*.rs 中加载模块内容

#### 代码可见性
- 默认情况下，所有类型（函数、方法、结构体、枚举……）都是私有的
- 父模块无法访问子模块中的私有项，而子模块可以访问父模块及更上层的模块的私有项
- 使用 pub 关键字将模块、函数等标为对外可见的
- 结构体与枚举的可见性
    - 仅将结构体设置为 pub，其内部所有字段仍然是私有的
    - 仅将枚举设置为 pub，则其内部所有字段都对外可见

#### use 引入
- 使用 use 关键字来引入模块或类型，来简化调用
- 要避免同名调用
- 使用 as 来设置别名解决冲突问题，例如：
    ```rust
    use std::fmt::Result;
    use std::io::Result as IoResult;
    ```
- 利用 use 导出，如：
    ```rust
    mod A {
        pub mod B {
            pub fn func_b() {}
        }
    }
    pub use crate::A::B;
    pub fn func() {
        B::func_b();
    }
    ```
    - 从外部调用的时候也可以直接使用 B 模块
- 可以使用 {} 来简化
    ```rust
    use std::collections::{
        HashMap,
        BTreeMap,
        HashSet
    };
    use std::{cmp::Ordering, io};
    ```
    - {} 中可以使用 self：
        ```rust
        use std::io::{self, Write}
        // 即 use std::io 以及 use std::io::Write
        ```
- 使用 * 引入模块下所有公开项，如 `#!rust use std::collections::*;`，但要小心名称冲突

#### 使用第三方包
例如使用 rand 包：

1. 修改 Cargo.toml，在 [dependencies] 中添加 rand = "0.8.3"
2. 在代码中使用 rand::... 即可
    ```rust
    use rand::Rng; // trait
    fn main() {
        let n = rand::thread_rng().gen_range(1..101);
    }
    ```

可以在 [crates.io](https://crates.io) 或 [lib.rs](https://lib.rs) 中检索使用第三方包

#### 受限可见性
- `#!rust pub` 表示无任何限制的完全可见
- `#!rust pub(crate)` 表示在当前包内可见
- `#!rust pub(self)` 表示在当前模块中可见
- `#!rust pub(super)` 表示在父模块中可见
- `#!rust pub(in <path>)` 表示在 <path\> 代表的模块中可见

#### 三种模块目录组织方式
- Rust 2015
    ```text
    .
    ├── lib.rs
    └── foo/
        ├── mod.rs
        └── bar.rs
    ```
    - lib.rs 中 mod foo; 会引入 foo/mod.rs 中内容
    - 需要在 foo/mod.rs 中继续为 bar.rs 创建同名 mod
- Rust 2018
    ```text
    .
    ├── lib.rs
    ├── foo.rs
    └── foo/
        └── bar.rs
    ```
    - lib.rs 中 mod foo; 会引入 foo.rs
    - 在 foo.rs 中 mod bar;
    - 与 2015 的模式相比就相当于将 mod.rs 提到文件夹外的同名文件了
- 使用 \#[path = ...] 创建模块（慎用）
    ```text
    .
    ├── lib.rs       
    └── pkg/        // 任意
        ├── foo.rs
        └── bar.rs
    ```
    - lib.rs 中在 mod foo; 前指定路径：
        ```rust
        #[path = "./pkg/foo.rs"]
        pub mod foo;

        #[path = "./pkg/bar.rs"]
        pub mod bar;
        ```

## 注释与文档
Rust 中注释分为两类：

- 代码注释：说明某一段代码的作用（// 行注释和 /\* ... \*/ 块注释）
- 文档注释：使用 markdown 语法，描述项目、介绍功能、生成文档
    - 包和模块注释：说明当前包和模块的功能

### 文档注释
- 文档行注释 /// 与文档块注释 /\*\* ... \*/
    - 文档注释需要位于库类型的 crate 中
    - 可以使用 markdown 语法，以及代码块高亮显示
    - 写在被注释类型上方
    - 被注释的对象需要 pub 对外可见
    - 文档注释中可以直接使用多个一级标题，常用的有
        - \# Examples
        - \# Panics：描述函数可能会出现的 panic 情况
        - \# Errors：描述可能会出现的错误以及触发情况
        - \# Safety：unsafe 代码需要注意的使用条件
- 包/模块级别行注释 //! 与包/模块级别块注释 /\*! ... \*/
    - 写在 crate root 的最上方
- 使用 cargo doc 构建文档，生成在 target/doc 目录下
    - 使用 cargo doc --open 构建并打开
- 文档测试
    - 文档注释中的代码块可以用作测试，直接写 assert 等宏就可以
    - 使用 cargo test 会进行测试，并显示 "Doc-tests ..."
    - 预期会造成 panic 等代码块需要在代码块语言后加上 should_panic：
        ````rust
        /// # Panics
        /// 
        /// ```rust,should_panic
        /// ...
        /// ```
        ````
    - 仅测试，不显示在文档中的行开头加 # 就可以：
        ```rust
        /// ```
        /// # fn try_main() -> Result<(), String> {
        /// let res = ...::func()?;
        /// #     Ok(())
        /// # }
        /// # fn main() {
        /// #     try_main().unwrap();
        /// # }
        ```
        - 如上述例子，最终在文档中只会显示 let 那一行，但在进行 doc-test 时全部代码都会运行
- 代码跳转（自动链接）
    - 文档中写 [\`Option\`] 会在文档中创建一个指向标准库中 Option 类型的链接
    - 也可以指定具体的路径来创建指向自己代码或其它库中指定项的链接
    - 同名项可以标示类型：
        ```rust
        /// 跳转到结构体  [`Foo`](struct@Foo)
        pub struct Bar;

        /// 跳转到同名函数 [`Foo`](fn@Foo)
        pub struct Foo {}

        /// 跳转到同名宏 [`foo!`]
        pub fn Foo() {}

        #[macro_export]
        macro_rules! foo {
          () => {}
        }
        ```
- 文档搜索别名
    ```rust
    #[doc(alias = "x")]
    #[doc(alias = "big")]
    pub struct BigX;

    #[doc(alias("y", "big"))]
    pub struct BigY;
    ```
    - 如上代码，在文档中搜索的时候，搜索 x 就会命中 BigX

## 格式化输出
Rust 的格式化就比较类似于 python 的 format 了

- 格式化宏
    - print!：格式化文本到标准输出，不换行
    - println!：格式化文本到标准输出，换行
    - format!：格式化文本，返回 String
    - eprint! 与 eprintln!：格式化到标准错误输出
- 占位符
    - {} 适用于实现了 std::fmt::Display trait 的类型，用于展示给用户
    - {:?} 适用于实现了 std::fmt::Debug trait 的类型，用于调试
    - {:#?} 同上，不过显示更优美（自动换行一类）
- 实现 Display trait
    ```rust
    use std::fmt;
    impl fmt::Display for ... {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "...{}...", ...)
        }
    }
    ```
    - 只能为当前作用域中的类型实现 Display trait
    - 为外部类型实现 Display 可以使用 newtype 模式
- 位置参数
    ```rust
    fn main() {
        println!("{}{}", 1, 2); // =>"12"
        println!("{1}{0}", 1, 2); // =>"21"
        // => Alice, this is Bob. Bob, this is Alice
        println!("{0}, this is {1}. {1}, this is {0}", "Alice", "Bob");
        println!("{1}{}{0}{}", 1, 2); // => 2112
    }
    ```
    - 对于 {:?} 或 {:#?}，将位置参数加在冒号前就可以
- 具名参数
    ```rust
    fn main() {
        println!("{argument}", argument = "test"); // => "test"
        println!("{name} {}", 1, name = 2); // => "2 1"
        println!("{a} {c} {b}", a = "a", b = 'b', c = 3); // => "a 3 b"
    }
    ```
    - 带名称的参数只能放在不带名称的后面
- 格式化参数
    - 宽度填充
        - 字符串
            ```rust
            //-----------------------------------
            // 以下全部输出 "Hello x    !"
            // 为"x"后面填充空格，补齐宽度5
            println!("Hello {:5}!", "x");
            // 使用参数5来指定宽度
            println!("Hello {:1$}!", "x", 5);
            // 使用x作为占位符输出内容，同时使用5作为宽度
            println!("Hello {1:0$}!", 5, "x");
            // 使用有名称的参数作为宽度
            println!("Hello {:width$}!", "x", width = 5);
            //-----------------------------------
            
            // 使用参数5为参数x指定宽度，同时在结尾输出参数5 => Hello x    !5
            println!("Hello {:1$}!{}", "x", 5);
            ```
        - 数字
            ```rust
            // 宽度是5 => Hello     5!
            println!("Hello {:5}!", 5);
            // 显式的输出正号 => Hello +5!
            println!("Hello {:+}!", 5);
            // 宽度5，使用0进行填充 => Hello 00005!
            println!("Hello {:05}!", 5);
            // 负号也要占用一位宽度 => Hello -0005!
            println!("Hello {:05}!", -5);
            ```
        - 对齐
            ```rust
            // 以下全部都会补齐5个字符的长度
            // 左对齐 => Hello x    !
            println!("Hello {:<5}!", "x");
            // 右对齐 => Hello     x!
            println!("Hello {:>5}!", "x");
            // 居中对齐 => Hello   x  !
            println!("Hello {:^5}!", "x");

            // 对齐并使用指定符号填充 => Hello x&&&&!
            // 指定符号填充的前提条件是必须有对齐字符
            println!("Hello {:&<5}!", "x");
            ```
    - 精度
        ```rust
        let v = 3.1415926;
        // 保留小数点后两位 => 3.14
        println!("{:.2}", v);
        // 带符号保留小数点后两位 => +3.14
        println!("{:+.2}", v);
        // 不带小数 => 3
        println!("{:.0}", v);
        // 通过参数来设定精度 => 3.1416，相当于{:.4}
        println!("{:.1$}", v, 4);

        let s = "abcded";
        // 保留字符串前三个字符 => abc
        println!("{:.3}", s);
        // {:.*}接收两个参数，第一个是精度，第二个是被格式化的值 => Hello abc!
        println!("Hello {:.*}!", 3, "abcdefg");
        ```
    - 进制
        ```rust
        // 二进制 => 0b11011!
        println!("{:#b}!", 27);
        // 八进制 => 0o33!
        println!("{:#o}!", 27);
        // 十进制 => 27!
        println!("{}!", 27);
        // 小写十六进制 => 0x1b!
        println!("{:#x}!", 27);
        // 大写十六进制 => 0x1B!
        println!("{:#X}!", 27);

        // 不带前缀的十六进制 => 1b!
        println!("{:x}!", 27);

        // 使用0填充二进制，宽度为10 => 0b00011011!
        println!("{:#010b}!", 27);
        ```
    - 指数
        ```rust
        println!("{:2e}", 1000000000); // => 1e9
        println!("{:2E}", 1000000000); // => 1E9
        ```
    - 指针地址
        ```rust
        let v = vec![1, 2, 3];
        println!("{:p}", v.as_ptr()) // => 0x600002324050
        ```
    - 输出 { 或 } 要写两次进行转义
- 1.58 中新增捕获环境值
    - 类似 python 中的 f-string，不过不需要特殊标注
    - 捕获变量可以替换在任何位置
        ```rust
        let (width, precision) = get_format();
        for (name, score) in get_scores() {
            println!("{name}: {score:width$.precision$}");
        }
        ```
    - panic! 在 2021 版本下才可以这样使用

## 生命周期
- 存在多个引用时，编译器有时会无法自动推导生命周期，需要手动标注
- 生命周期是为编译器而标注，并不会改变任何引用的实际作用域
- 生命周期以 ' 开头，名称往往是单独的小写字母（如 `#!rust 'a`）
    ```rust
    &i32        // i32 类型的引用
    &'a i32     // 带有显示生命周期 'a 的 i32 引用
    &'a mut i32 // 带有显示生命周期 'a 的 i32 可变引用
    ```
- 函数签名中使用生命周期需要先像泛型一样声明
    ```rust
    fn func<'a>(x: &'a str, y: &'a str) -> &'a str {}
    ```
    - 表示两个参数以及返回引用至少和 'a 活得一样久
    - 两个参数的真实生命周期可能是不一样的，只需要不小于 'a 就可以
    - 调用的时候不必标注生命周期
- 生命周期语法用来将函数的多个引用参数和返回值的作用域关联到一起，避免了悬垂引用
    - 返回值是引用时，其生命周期只能来自参数，来自函数体内部的话就是悬垂引用
- 结构体中生命周期
    - 结构体中使用生命周期可以保证内部引用类型的参数活得比结构体本身长
        ```rust
        struct MyStruct<'a> {
            string: &'a str,
        }
        ```
    - 如下例即是结构体获得比内部参数长，会报错：
        ```rust
        let i;
        {
            let string = String::from("test");
            i = MyStruct {
                string: string.as_str()
            };
        }
        println!("{:?}", i);
        ```
- 生命周期消除
    - 有时编译器可以自动推测生命周期，不需要显示标注
    - 消除规则（推测规则）
        - 默认情况下每一个引用参数都会获得一个独自的生命周期
        - 如果只有一个输入生命周期（参数的生命周期，即只有一个引用类型参数），则该生命周期会被赋给所有输出生命周期
        - 如果存在多个输入生命周期，但其中一个是 `#!rust &self` 或 `#!rust &mut self`，则 self 的生命周期会被赋给所有输出生命周期
    - 闭包不会遵循这个规则
    - impl 块生命周期消除（即省略）
        - impl 块中没有用到的生命周期可以使用 '_ 来进行省略：
            ```rust
            impl<'a> ... for ...<'a> {} 
            impl ... for ...<'_> {}
            ```
- 为带有生命周期的结构体实现方法
    - 需要像泛型一样为 impl 和结构体名都标注上生命周期
        ```rust
        impl<'a> MyStruct<'a> {
            fn method(&self, another_str: &str) -> &str {
                println!("{}", another_str);
                self.string
            }
        }
        ```
        - 上面例子中可以不为 method 标注生命周期，因为根据上面消除规则的第一和第三条，会自动推测为返回值标上和 `#!rust &self` 一样的生命周期
- 生命周期约束
    - 如想要为上面 method 的返回值赋上和 another_str 一样的生命周期，则需要保证这个生命周期要比 self 的生命周期小，使用 `#!rust 'a: 'b` 语法来表示 'a 一定不小于 'b
        ```rust
        impl<'a: 'b, 'b> MyStruct<'a> {
            fn method(&'a self, another: &'b str) -> &'b str {
                println!("{}", another);
                self.string
            }
        }
        ```
        - 或者使用 where 来单独对一个方法进行约束：
            ```rust
            impl<'a> MyStruct<'a> {
                fn method<'b>(&'a self, another: &'b str) -> &'b str
                    where 'a: 'b
                {
                    println!("{}", another);
                    self.string
                }
            }
            ```
    - T: 'a 表示类型 T 必须获得比 'a 久：
        ```rust 
        struct Ref<'a, T: 'a> {
            r: &'a T
        }
        ```
- 静态生命周期
    - 和整个程序活得一样久的引用可以使用 'static 来标注（例如字符串字面量）
    - &'static 仅针对引用，而不是持有该引用的变量
    - 取悦编译器可以使用 T: 'static，即使 T 不是 static 的
        ```rust
        fn static_bound<T: Display + 'static>(t: &T) {
            println!("{}", t);
        }
        fn main() {
            let s1 = "String".to_string();
            static_bound(&s1);
        }
        ```
- NLL（Non-Lexical Lifetime）规则
    - Rust 1.31 后引用的生命周期从借用处开始一直持续到 **最后一次使用的地方**
- Reborrow 再借用
    ```rust
    let mut p = Point {x: 0, y: 0};
    let r = &mut p;
    let rr: &Point = &*r;
    println!("{:?}", rr);
    r.move_to(10, 10)
    println!("{:?}", r);
    ```
    - 可变借用和不可变的它的再借用可以同时存在，但是不能在再借用的生命周期内使用可变借用。也就是上面例子中在 rr 的生命周期内不能使用 r（rr 的生命周期由于 NLL 规则，到第一个 println! 的时候就已经结束了，后面可以继续使用 r）

## 闭包和迭代器
### 闭包
- 一种匿名函数，可以赋值给变量也可以作为参数传递给函数，但可以捕获调用者作用域中的值
    ```rust
    let x = 1;
    let sum = |y| x + y;
    assert_eq!(3, sum(2));
    ```
- 闭包语法：
    ```rust
    |para1, para2, ...| {
        statement1;
        statement2;
        expression
    }
    |para1, para2, ...| expression
    ```
- 类型推导
    - 闭包不会作为 api 对外提供，可以直接依靠编译器的类型推导能力，无需手动标注
        ```rust
        let sum = |x, y| x + y;
        let v = sum(1, 2) // 编译器通过这句推导出类型
        ````
    - 但当闭包只声明没有使用时，编译器并不能推导出类型，需要手动标注
    - 当编译器推导出一种类型之后，就会一直使用该类型，而不能将闭包当作泛型使用
- 结构体中存储闭包
    ```rust
    struct Cacher<T, E>
        where T: Fn(E) -> E,
              E: Copy
    {
        query: T,
        value: Option<E>,
    }
    ```
    - 闭包类型一定要通过泛型来定义，因为不同实现的类型都是不一样的，要求仅仅是实现 Fn(E) -> E 这个 trait，即输入 E 返回 E
- 三种 Fn trait
    - FnOnce：只能运行一次（会带走被捕获变量的所有权）
        - 带走所有权的例子：
            ```rust
                let x = String::from("test");
                let sum = |y| x + y;
                println!("{}", sum("test"));
                println!("{}", x); // 报错，因为所有权进入了闭包中    
            ```
        - 仅实现了 FnOnce 的闭包在调用时会转移所有权，不能调用两次：
            ```rust
            fn fn_once<F>(func: F)
                where F: FnOnce(usize) -> bool
            {
                func(1);
                func(2); // 报错
            }
            ```
            - 但是给 F 加一个 Copy 的约束则可以调用多次
        - 在参数列表前加 move 关键字强制闭包获取捕获变量的所有权（聚焦于如何捕获变量）
    - FnMut：以可变借用方式捕获环境中的值
        - 直接调用时需要将闭包标记为 mut
            ```rust
            let mut s = String::new();
            let mut update_string = |st| s.push_str(st);
            update_string("test");
            ```
        - 当作变量时不需要标记为 mut
            ```rust
            fn exec<'a, F: FnMut(&'a str)>(mut f: F) { // 这里需要 mut
                f("test");
            }
            fn main() {
                let mut s = String::new();
                let update_string = |st| s.push_str(st); // 这里不需要 mut
                exec(update_string);
            }
            ```
    - Fn：以不可变借用的方式捕获环境中的值
    - 一个闭包实现了哪种 Fn trait 取决于该闭包**如何使用**被捕获的变量，而不是如何捕获。而 move 则关注于如何捕获，有 move 则强制获取所有权
        - 使用了 move 关键字仍然可以实现 Fn trait（当闭包对于捕获变量的使用仅仅是不可变借用时）
    - 三种 Fn 的关系
        ```rust
        pub trait Fn<Args> : FnMut<Args> {
            extern "rust-call" fn call(&self, args: Args) -> Self::Output;
        }

        pub trait FnMut<Args> : FnOnce<Args> {
            extern "rust-call" fn call_mut(&mut self, args: Args) -> Self::Output;
        }

        pub trait FnOnce<Args> {
            type Output;
            extern "rust-call" fn call_once(self, args: Args) -> Self::Output;
        }
        ```
        - 所有闭包都会实现 FnOnce trait，因为至少可以被调用一次
        - 没有移出捕获变量所有权的闭包自动实现 FnMut trait
        - 不需要对捕获变量进行改变的闭包自动实现 Fn trait
        - 实现 Fn 的前提是实现 FnMut，实现 FnMut 的前提是实现 FnOnce
        - Fn 获取 &self、FnMut 获取 &mut self、FnOnce 获取 self
        - 建议先使用 Fn，然后靠编译器来判断正误以及如何选择
- 闭包作为返回值
    - 不能使用 Fn(...) -> ... 作为返回值，因为它是特征，没有固定内存大小
    - 可以使用 impl Fn(...) -> ... 作为返回值
    - 可以使用特征对象，即 Box<dyn Fn(...) -\> ...\> 的形式

### 迭代器
- for 循环遍历数组实际上是在数组上调用了 into_iter 方法（来自 IntoIterator trait）
- Iterator trait
    ```rust
    pub trait Iterator {
        type Item;
        fn next(&mut self) -> Option<Self::Item>;
    }
    ```
    - next 方法有值时返回 Some(...)，迭代结束则返回 None
    - 手动迭代必须声明迭代器为 mut
    - 仅需要实现 next 方法，其它方法有默认实现
- IntoIterator trait
    - Iterator 自动实现 IntoIterator
        ```rust
        impl<I: Iterator> IntoIterator for I {
            type Item = I::Item;
            type IntoIter = I;
            #[inline]
            fn into_iter(self) -> I { self }
        }
        ```
- into_iter、iter、iter_mut
    - .into_iter 会夺走所有权
    - .iter 是不可变借用，调用 next 返回 Some(&T)
    - .iter_mut 是可变借用，调用 next 返回 Some(&mut T)
- 消费者适配器
    - 内部调用了 next 的迭代器方法，会消耗迭代器上元素，返回其它值，称为消费者适配器
    - 例如 .sum 方法，内部调用 next 来对所有元素求和，也会拿走迭代器的所有权
    - collect 方法可以将迭代器中的值收集到集合类型中，但需要先标注要收集到的类型
        ```rust
        let v: Vec<_> = iterator.collect();
        ```
- 迭代器适配器
    - 迭代器适配器或返回新的迭代器
    - 例如 .map .filter .zip
    - 可以进行链式调用，一般使用 collect 收尾收集元素

## 深入类型
- newtype
    - 即使用一个元组结构体来包装
    - 可以为外部类型实现外部 trait
    - 可以具有更好的可读性，以及可以实现类型异化
- 类型别名
    - 如 `#!rust type Meters = u32`
    - 仅仅是别名，并不是全新类型，即上面 Meters 类型和 u32 在编译器眼里没有区别
    - 可以增加可读性、简化代码
- 用不返回类型 !
    - 对于 match，各分支返回的类型需要一致，但如果有分支返回 ! 类型，则可以忽略这个分支
- 定长类型与不定长类型
    - 定长类型自动实现 Sized trait，并且在使用泛型的时候会自动添加 Sized 约束
    - 不定长类型（动态大小类型，DST），包括切片、str、特征等（Vec 等集合类型是定长的，因为在栈上存储的信息定长）
        - DST 无法单独使用，只能通过引用或者 Box 来间接使用，如将特征封装为特征对象
        - ?Size 特征表示既有可能是固定大小类型也有可能是 DST：
            ```rust
            fn func<T: ?Sized>(t: &T) {}
            ```
        - 将 str 包裹为 Box<str\> 不能直接使用 Box::new("..." as str)，因为这里并不能知道 str 的大小。可以使用 .into() 来让编译器来转换类型（将 &str 转为 Box）
            ```rust
            let s: Box<str> = "...".into();
            ```
- 整数与枚举的类型转换
    ```rust
    enum MyEnum {
        A = 1,
        B = 2,
        C = 3,
    }
    ```
    - 将枚举转换为整数可以直接使用 as：
        ```rust
        let x = MyEnum::A as i32;
        ```
    - 整数转为枚举则相对复杂，有几种方法
        - 使用第三方库：num-traits num-derive 或 num_enums 等
        - 使用 TryFrom trait
            ```rust
            use std::convert::TryFrom;
            impl TryFrom<i32> for MyEnum {
                type Error = ();
                fn try_from(v: i32) -> Result<Self, Self::Error> {
                    match v {
                        x if x == MyEnum::A as i32 => Ok(MyEnum::A),
                        x if x == MyEnum::B as i32 => Ok(MyEnum::B),
                        x if x == MyEnum::C as i32 => Ok(MyEnum::C),
                        _ => Err(()),
                    }
                }
            }
            ```
            - 为 MyEnum 实现了 TryFrom<i32\> 后就可以调用 i32.try_into() 来尝试转为 MyEnum 了
                ```rust
                let x = 1
                match x.try_into() {
                    Ok(EyEnum::A) => ...,
                    ...
                }
                ```
        - 使用 unsafe transmute 转换
            ```rust
            #[repr(i32)] // 规定内部存储为 i32
            enum MyEnum {
                ...
            }

            let x: i32 = 1;
            let y: MyEnum = unsafe { std::mem::transmute(x) };
            ```

## 智能指针
- 引用仅是借用数据，而智能指针往往可以拥有指向的数据
- 智能指针实现了 Deref 和 Drop trait
    - Deref 让智能指针可以像引用一样工作
    - Drop 允许指定智能指针超出作用域后自动执行的代码

### Deref trait
- `#!rust use std::ops::Deref`
- 实现了 Deref 之后就可以使用 * 解引用了
    ```rust
    use std::ops::Deref
    struct MyBox<T>(T);
    impl<T> MyBox<T> {
        fn new(x: T) -> MyBox<T> { MyBox(x) }
    }
    impl<T> Deref for MyBox<T> {
        type Target = T;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    ```
    - deref 返回内部值的正常引用，可以使用 * 来解引用
    - 对 MyBox 进行解引用时实际上调用的是 `#!rust *(x.deref())`
- 参数中隐式 Deref 转换
    ```rust
    fn func(s: &str) { println!("{}", s) }
    fn main() {
        let s = MyBox::new(String::from("..."));
        func(&s);
    }
    ```
    - 调用时 &s: &MyBox<String\> -> &String -> &str
- 引用归一化
    - 智能指针会从结构体中脱壳出来得到内部的引用类型
    - 多重引用可以归一化
        ```rust
        impl<T: ?Sized> Deref for &T {
            type Target = T;
            fn deref(&self) -> &T {
                *self  // 这里 self 是 &&T 类型
            }
        }
        ```
- DerefMut 与 Deref
    - 当 T: Deref<Target=U\> 时，&T 可以转换为 &U、&mut T 也可以转换为 &U（rust 可以把可变引用隐式转换为不可变引用）
    - 当 T: DerefMut<Target=U\> 时，&mut T 可以转换为 &mut U
    - 实现 DerefMut trait 需要先实现 Deref
        ```rust
        use std::ops::DerefMut;
        impl<T> DerefMut for MyBox<T> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
        ```

### Drop trait
- 变量离开作用域的时候会自动执行 Drop trait 的 drop 方法
- 可以为结构体自定义 drop
    ```rust
    struct A;
    struct B;
    impl Drop for A { fn drop(&mut self) { println!("drop A") } }
    impl Drop for B { fn drop(&mut self) { println!("drop B") } }
    struct C {
        a: A,
        b: B,
    }
    impl Drop for C { fn drop(&mut self) { println!("drop C") } }
    fn main() {
        let x = C { a: A, b: B };
        println!("end");
    }
    // end
    // drop C
    // drop A
    // drop B
    ```
    - drop 方法借用目标使用的是可变引用，不会拿走所有权
    - 结构体每个字段都会 drop
    - 先声明的变量后 drop、结构体内部按顺序依次 drop
    - 即使 C 不手动实现 Drop，也会调用到 A 和 B 的 drop，因为会为 C 提供默认的 Drop 实现
- .drop 函数不能手动调用，因为它是借用，后面依然可以访问原值，但是可能已经被清理了
    - 使用 std::mem::drop 函数（在 prelude 中）来手动 drop
    - std::mem::drop 的签名：`#!rust pub fn drop<T>(_x: T)`
    - 这个 drop 是一个空实现，它可以带走目标的所有权，然后这个函数直接结束，目标的作用域也就结束了，导致自动调用 drop 方法来释放
- 无法为同一个类型实现 Copy 和 Drop

### Box
- Box<T\> 允许将一个值分配到堆上，然后在栈上保留一个智能指针指向堆上数据
- 可以将数据分配到堆上
    ```rust
    let a = Box::new(3);
    println!("a = {}", a); // 利用 Deref 自动解引用
    let b = *a + 1; // 表达式中需要手动解引用
    ```
    - 但是 Box::new 会先在栈上分配空间然后移到堆上，比如 Box::new([0; 1000000000000]) 会报错栈溢出
- 避免栈上数据拷贝
    - 栈上数据所有权转移的时候会拷贝一份数据，但在堆上时堆上数据不会拷贝，仅仅需要拷贝一份栈上的指针即可完成所有权转移
- 将 DST 变为固定大小类型
    - 如递归类型，rust 不知道递归类型需要多少空间，但包裹一层 Box 则可以变成固定大小
        ```rust
        enum List {
            Cons(i32, Box<List>),
            Nil,
        }
        ```
- 将特征转为特征对象
- Box::leak
    - 消费掉 Box，并强制目标值从内存中泄露
    - 例如将 String 类型变成拥有 'static 生命周期的 &str 类型
        ```rust
        fn func() -> &'static str {
            let mut s = String::new();
            s.push_str("...");
            Box::leak(s.into_boxed_str())
        }
        ```

### Rc 与 Arc
- Rc 即引用计数（reference counting），记录一个数据被引用的次数来确定数据是否被使用，当引用次数归零，则清理释放
- 使用 clone 来复制智能指针并增加引用计数
    ```rust
    use std::rc::Rc
    let a = Rc::new(String::from("..."));
    let b = Rc::clone(&a);
    assert_eq!(2, Rc::strong_count(&a));
    assert_eq!(2, Rc::strong_count(&b));
    ```
    - 使用 Rc::strong_count 来获取计数
- Rc 在离开作用域时会被释放，并将引用数据的计数减一
- Rc 是指向底层数据的不可变引用，无法通过它来修改数据
- Rc 只能用在同一线程内部，多线程之间共享需要使用 Arc（Atomic Rc），其 api 一致但是线程安全的，不过效率会有所降低
    - 需要 `#!rust use std::sync::Arc`

### Cell 与 RefCell
Cell<T\> 适用于 T 实现 Copy 的情况，而没有 Copy 的话则不能使用 Cell 只能使用 RefCell。二者都可以达到内部可变性的效果

Rust 规定一个结构体中的字段要么都是 immutable 要么都是 mutable，而不能将部分字段标记为 mutable。但可以使用 Cell 或 RefCell 包裹想要可变的字段，这样就实现了 immutable 结构体中部分字段可变的效果而不必将整个结构体标记为 mutable

#### Cell
- `#!rust use std::cell::Cell;`
- .get() 取值（Copy 出来）
- 可以使用 .set() 设置新值而不需要将其标记为 mut
    ```rust
    let c = Cell::new("abcd");
    let a = c.get();
    c.set("efgh");
    let b = c.get();
    println!("{} {}", a, b); // abcd efgh
    ```
- 例：
    - 下面代码会报错：
        ```rust
        let mut x = 1;
        let y = &mut x;
        let z = &mut x;
        x = 2; *y = 3; *z = 4;
        println!("{}", x);
        ```
    - 而下面的不会：
        ```rust
        let x = Cell::new(1);
        let y = &x;
        let z = &x;
        x.set(2); y.set(3); z.set(4);
        println!("{}", x.get());
        ```
        - 这里 x 也不必声明为 mut，y z 都是 x 的不可变引用，可以共存
        - 但可以通过 x y z 来改变 cell 中的值
- Cell 没有性能损耗
- Rust 1.37 中增加了两个方法，可以很好地解决借用冲突：
    - Cell::from_mut，将 &mut T 转为 &Cell<T\>
    - Cell::as_slice_of_cells，将 &Cell<[T]\> 转为 &[Cell<T\>]

#### RefCell
- `#!rust use std::cell::RefCell;`
- 可以使编译期可变和不可变引用共存
- 使用时可变和不可变引用一样不能共存，会 panic，并不能依次绕过借用规则
- 与 Cell 提供值相比，RefCell 提供引用
    - .borrow() 创建不可变引用、.borrow_mut() 创建可变引用
- RefCell 适用于编译期误报或者一个引用在多处使用难以管理借用关系时
- 可以利用 RefCell 来创建一个不是 mut 但是内部值可变的东西
    ```rust
    use std::cell::RefCell;
    pub trait Messenger {
        fn send(&self, msg: String); // 定义时不是 &mut self
    }
    pub struct MsgQueue {
        msg_cache: RefCell<Vec<String>>,
    }
    impl Messenger for MsgQueue {
        fn send(&self, msg: String) {
            self.msg_cache.borrow_mut().push(msg) // self 不是 mut 的，msg_cache 也就不是 mut 的
        }
    }
    ```
- Rc 和 RefCell 组合使用，可以同时拥有多个所有者并实现数据的可变性：
    ```rust
    use std::cell::RefCell;
    use std::rc::Rc;
    fn main() {
        let s = Rc::new(RefCell::new("...".to_string()));
        let s1 = s.clone();
        let s2 = s.clone();
        s2.borrow_mut().push_str("...");
        println!("{:?}\n{:?}\n{:?}", s, s1, s2);
    }
    ```
    - 会输出三遍 `RefCell { value: "......" }`
    - 组合使用性能其实很高

### Weak 弱引用
- `#!rust use std::rc::Weak`
- 使用 Rc 配合 RefCell 会构造出两个指针互相指也就是循环引用的情况，可能会造成引用计数无法清零不会 drop 从而造成内存泄漏
- 使用 Weak 可以解决循环引用的问题，它并不保证引用关系会存在，与 Rc 相比，它的特点：
    - 不会计数
    - 不拥有值的所有权
    - 不会阻止值的释放（Rc 只有当计数为 0 时才能 drop）
- Weak 在使用时需要先调用 upgrade 方法得到一个 Option<Rc<T\>\> 类型的值（当引用值存在时返回 Some(rc)，取出 Rc 使用，不存在时返回 None）
- 在 Rc<T\> 上调用 downgrade 方法即可获得 Weak<T\>，同时会计入到该 Rc 的一个 weak_count 上
- 当会造成循环引用时，将其中一支换为 Weak 即可避免

## 多线程并发编程
### 使用线程
- 创建线程
    - 使用 std\:\:thread::spawn 创建线程
    - 线程内部代码使用闭包来执行
    - main 线程结束则程序立即结束不会等到子线程全部结束
    - thread::sleep 休眠当前线程指定时间
    ```rust
    use std::thread;
    use std::time::Duration;
    fn main() {
        thread::spawn(|| {
            for i in 1..10 {
                println!("hi number {} from the spawned thread!", i);
                thread::sleep(Duration::from_millis(1));
            }
        });
        for i in 1..5 {
            println!("hi number {} from the main thread!", i);
            thread::sleep(Duration::from_millis(1));
        }
    }
    ```
- 等待子线程结束
    - spawn 会返回一个 JoinHandle<()\> 类型的值，可以在其上调用 .join 方法来阻塞当前线程
    ```rust
    let handle = thread::spawn(...)
    handle.join().unwrap();
    ```
- 线程闭包中捕获变量
    - 创建线程的闭包中不能直接使用当前线程中的变量，因为无法确定创建的新线程会存活多久，可能在借用变量创建新线程，在新线程运行时，借用的原值已经被 drop
    - 因此使用捕获变量的话一定要在参数列表前加上 move 关键字来强制转移所有权（也就是说当前线程后面将不可以在使用这个变量）
- barrier
    - 在多个线程内同步，即等待各线程执行到同一位置后再继续执行
    - 使用 std::sync::Barrier，需要通过 Arc 来分配到各个线程中
    - 调用其 .wait() 方法来对所有使用了 barrier 对线程进行同步
    ```rust
    use std::sync::{Arc, Barrier};
    use std::thread;
    fn main() {
        let mut handles = Vec::with_capacity(6);
        let barrier = Arc::new(Barrier::new(6));
        for _ in 0..=5 {
            let b = barrier.clone();
            handles.push(thread::spawn(move || {
                println!("before wait");
                b.wait();
                println!("after wait");
            }))
        }
        for handle in handles {
            handle.join().unwrap();
        }
    }
    ```
- 线程局部变量
    - 标准库 thread_local 宏
        - 通过宏来创建一个生命周期为 'static 的线程局部变量
        - 每个线程访问时都会使用它的初始值，且各线程间彼此不干扰
        - 线程内部使用这个变量的 with 方法来获取值进行操作
        ```rust
        use std::cell::RefCell;
        use std::thread;
        thread_local!(static FOO: RefCell<u32> = RefCell::new(1));
        FOO.with(|f| { ... })
        thread::spawn(move || {
            FOO.with(|f| { ... })
        }).join().unwrap();
        ```
    - 第三方库 thread-local

**TODO：歇逼了，以后有时间有耐心了再看多线程**

## 全局变量
- 编译期初始化
    - 静态常量
        - 使用 const 定义，必须指定类型，命名一般全大写
        - 可以在任意作用域定义，生命周期贯穿整个程序
        - 赋值只能是在编译期就能计算的表达式
        - 不允许出现重复定义
    - 静态变量
        - 使用 static 定义，必须指定类型，命名一般全大写
        - 必须使用 unsafe 语句块才能访问和修改 static 变量
        - 只有在同一线程内或者不在乎多线程中数据准确性时才应该使用全局静态变量
        - 赋值只能是在编译期就能计算的表达式
        - 静态变量不会被内联，且整个程序中只有一个实例
        - 存储在静态变量中的值需要实现 Sync trait
    - 原子类型
        - 可以作为全局计数器，且是线程安全的
        ```rust
        use std::sync::atomic::{AtomicUsize. Ordering};
        static VAR: AtomicUsize = AtomicUsize::new(0);
        fn main() {
            for _ in 0..100 {
                VAR.fetch_add(1, Ordering::Relaxed);
            }
        }
        ```
- 运行期初始化
    - 使用 lazy_static 包中的 lazy_static 宏
    - 使用 Box::leak

## 错误处理
- 组合器
    - .or() .and() 对两个 Option / Result 进行类似布尔类型的操作返回其中一个，如：
        ```rust
        None.or(Some(1)) // -> Some(1)
        Ok("ok").and(Err("err")) // -> Err("err")
        ```
    - .or_else() .and_then() 第二个表达式是一个返回 Option / Result 的闭包，其他和 or and 用法一样
    - .filter() 可以对 Option 进行过滤
        ```rust
        let s1 = Some(3);
        let s2 = Some(6);
        let n = None;
        let fn_is_even = |x: &i8| x % 2 == 0;
        assert_eq!(s1.filter(fn_is_even), n);  // Some(3) -> 3 is not even -> None
        assert_eq!(s2.filter(fn_is_even), s2); // Some(6) -> 6 is even -> Some(6)
        assert_eq!(n.filter(fn_is_even), n);   // None -> no value -> None
        ```
    - .map() .map_err()
        - .map() 根据闭包将 Some 或 Ok 中的值更改为另一个
            ```rust
            Some("...").map(|s: &str| s.chars().count()) // -> Some(3)
            ```
        - .map_err() 同理，是将 Err 中的值更改为另一个
    - .map_or() .map_or_else()
        - .map_or() 包含两个参数，当调用者是 Ok / Some 时，执行第二个参数中的闭包，返回闭包的返回值；当调用者是 Err / None 时返回第一个参数作为默认值
        - .map_or_else() 类似 map_or，不过第一个参数即默认值也使用闭包来提供
    - .ok_or() .ok_or_else()
        - .ok_or() 将 Option 转换为 Result
            ```rust
            Some(1).ok_or("...") // -> Ok(1)
            None.ok_or("...") // -> Err("...")
            ```
        - .ok_or_else() 类似，但参数由闭包来提供
- 自定义错误类型
    - std::error::Error trait 定义
        ```rust
        use std::fmt::{Debug, Display};
        pub trait Error: Debug + Display {
            fn source(&self) -> Option<&(Error + 'static)> { /* 有默认实现 */ }
        }
        ```
        - 由此可见，自定义错误类型只需要自动 derive Debug，然后手动实现一下 Display trait
    - 自定义错误类型
        ```rust
        use std::fmt;
        #[derive(Debug)]
        struct MyError;
        impl fmt::Display for MyError {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "my error")
            }
        }
        fn func() -> Result<(), MyError> {
            Err(MyError)
        }
        ```
    - 错误转换 From trait
        ```rust
        #[derive(Debug)]
        struct MyError {
            message: String,
        }
        impl std::fmt::Display for MyError { ... }
        impl From<io::Error> for MyError {
            fn from(error: io::Error) -> Self {
                MyError {
                    message: error.to_string(),
                }
            }
        }
        ```
        - 这样实现了之后就可以在 ? 的时候支持自动将 io::Error 转换成 MyError
- 归一化错误类型
    - 例如将 std::env::VarError 和 std\:\:io::Error 归一化为同一种类型
    - 可以使用特征对象
    - 可以自定义 enum 错误类型，但是代码较复杂
    - 可以使用第三方包 thiserror 来简化自定义错误类型集合
        ```rust
        #[derive(thiserror::Error, Debug)]
        enum MyError {
            #[error("Environment variable not found")]
            EnvironmentVariableNotFound(#[from] std::env::VarError),
            #[error(transparent)]
            IOError(#[from] std::io::Error),
        }
        ```
    - 可以使用第三方包 anyhow 中的 anyhow::Result<T\>，不关心错误消息

## unsafe
unsafe 代码块有五种能力

- 解引用裸指针
- 调用一个 unsafe 或外部的函数
- 访问或修改一个可变的静态变量（前面介绍过了）
- 实现一个 unsafe trait
- 访问 union 中的字段

但 unsafe 代码块仍然受 rust 的安全支持，它并不能绕过 rust 的借用检查，也不能关闭任何 rust 的安全检查

### 解引用裸指针
- 裸指针
    - 裸指针不适用 Rust 的借用规则，同时拥有一个数据的可变和不可变指针
    - 裸指针不能保证指向合法的内存
    - 裸指针可以是 null
    - 裸指针没有实现任何自动的回收（drop）
    - 裸指针可以使用加减法（对地址操作），但是这不会考虑单元大小，建议对裸指针调用 .add 方法（会自动乘单元大小）
- 创建裸指针
    - 创建裸指针是 safe 的，不需要写在 unsafe 块中
    - 裸指针有两种写法：`#!rust *const T` 和 `#!rust *mut T` 分别表示 T 类型的不可变指针和可变指针（这里的 * 仅仅是记号，不表示解引用的含义）
    - 基于引用创建裸指针
        ```rust
        let mut num = 5;
        let r1 = &num as *const i32;
        let r2 = &mut num as *mut i32;
        ```
    - 基于内存地址创建裸指针
        ```rust
        let address = 0x012345usize;
        let r = address as *const i32;
        ```
        - 相当危险，但创建这样的裸指针仍然是 safe 的，只要不解引用
    - 基于智能指针创建裸指针
        ```rust
        let a: Box<i32> = Box::new(1);
        let b: *const i32 = &*a;
        let c: *const i32 = Box::into_raw(a)
        ```
    - 调用方法创建裸指针
        - 例如 String 的 .as_ptr() 和 .as_mut_ptr() 方法
- 解引用裸指针
    - 在 unsafe 块中可以直接使用 * 对裸指针进行解引用

### 调用 unsafe 或外部函数
#### unsafe 函数
- 使用 unsafe fn 定义
- 不能直接调用，只能在 unsafe 块中调用，即要确保认识到了正在调用的是一个不安全的函数
- 包含 unsafe 块的函数不必都标记为 unsafe 函数，因为有些函数虽然用了 unsafe，但操作实际上是完全安全的（编译器保守认为其不安全）

#### FFI
- 即 Foreign Function Interface，用来和其他语言进行交互
- rust 调用 c
    - 需要在 rust 代码中写明要调用的函数签名
    - 调用必须在 unsafe 块中进行
    - 例如调用 C 标准库中的 abs 函数
        ```rust
        extern "C" {
            fn abs(input: i32) -> i32;
        }
        fn main() {
            unsafe { println!("abs(-1) = {}", abs(-1)); }
        }
        ```
- c 调用 rust
    ```rust
    #[no_mangle]
    pub extern "C" fn call_from_c() {
        println!("Call from C");
    }
    ```
    - 使用 extern 创建一个接口
    - `#!rust #[no_mangle]` 告诉编译器不要修饰函数名
- 实用工具
    - 自动生成 FFI 接口
        - 生成 rust 调用 c 的代码：[:material-github: rust-lang/rust-bindgen](https://github.com/rust-lang/rust-bindgen)
        - 从 rust 代码生成 c bindings：[:material-github: eqrion/cbindgen](https://github.com/eqrion/cbindgen)
    - 与 C++ 代码交互（是安全的）：[:material-github: dtolnay/cxx](https://github.com/dtolnay/cxx)

### 实现 unsafe trait
- 至少有一个方法包含编译器无法验证的内容的 trait 会被标为 unsafe
- 定义使用 unsafe trait 定义
- 实现方法使用 unsafe impl

### 访问 union 中字段
- 类似结构体，但所有字段共用同一个存储空间，即向一个字段中写入值回覆盖其它字段
    ```rust
    #[repr(C)]
    union MyUnion {
        f1: u32,
        f2: f32,
    }
    ```
- 访问 union 字段是不安全的，因为 rust 无法保证当前存储在 union 实例中的数据类型，但写入是安全的


## macro 宏编程

### 声明式宏
- 使用 macro_rules! 进行定义，匹配代码并生成代码
    ```rust
    #[macro_export]
    macro_rules! myvec {
        ( $( $x:expr ),* ) => {
            {
                let mut tmp_vec = Vec::new();
                $(
                    tmp_vec.push($x);
                )*
                tmp_vec
            }
        };
    }
    ```
    - 宏名称不必加 !，但调用时需要加
    - `#!rust #[macro_export]` 用于导出宏，让其它包可以引入使用
    - 进行输入代码的模式匹配，使用 `#!rust ( $( $x:expr ),* )` 匹配多个以 , 分隔的表达式，每个记为 $x 供后面代码中使用，* 代表前面的模式可以出现任意次（包括 0）
    - => 后面是要生成的目标代码
    - 可以使用 `#!rust myvec![1, 2, 3]` 创建 Vec，也可以使用 `#!rust myvec!(...)` 或 `#!rust myvec!{...}`，这三者等价
- 详细用法 TODO：https://veykril.github.io/tlborm/

### 过程宏
- 过程宏的定义必须放入独立的 lib crate 中
- 自定义 derive 过程宏
    - 在当前 crate 根目录下创建一个新的 lib crate 用于编写宏
    - 新的 Cargo.toml 中需要添加
        ```toml
        [lib]
        proc-macro = true

        [dependencies]
        syn = "1.0"
        quote = "1.0"
        ```
    - lib.rs
        ```rust
        extern crate proc_macro;

        use proc_macro::TokenStream;
        use quote::quote;
        use syn;

        #[proc_macro_derive(HelloMacro)]
        pub fn hello_macro_derive(input: TokenStream) -> TokenStream {
            // 基于 input 构建 AST 语法树
            let ast = syn::parse(input).unwrap();

            // 构建特征实现代码
            impl_hello_macro(&ast)
        }
        ```
    - impl_hello_macro 函数
        ```rust
        fn impl_hello_macro(ast: &syn::DeriveInput) -> TokenStream {
            let name = &ast.ident;
            let gen = quote! {
                impl HelloMacro for #name {
                    fn hello_macro() {
                        println!("Hello, Macro! My name is {}!", stringify!(#name));
                    }
                }
            };
            gen.into()
        }
        ```
        - 读取 ast，使用 quote 生成代码，然后调用 .into 转换成 TokenStream
    - 导入这个 crate 之后就可以使用 `#!rust #[derive(HelloMacro)]` 生成代码自动实现 HelloMacro 了
- 类属性宏（attribute-like macros）
    - 例如修饰一个函数：
        ```rust
        #[route(GET, "/")]
        fn index() { ... }
        ```
    - 也需要一个独立的 crate 来定义，定义函数：
        ```rust
        #[proc_macro_attribute]
        pub fn route(attr: TokenStream, item: TokenStream) -> TokenStream {
            ...
        }
        ```
        - attr 是属性包含的内容，如上例子中的 GET, "/"
        - item 是标注的项，如上例子中的 fn index() { ... } 即整个函数体
- 类函数宏
    - 和声明宏的使用方式类似，但和前两种过程宏的定义方式类似
    - 例如如下调用解析 SQL 语句：
        ```rust
        let sql = sql!(SELECT * FROM posts WHERE id=1);
        ```
        - 需要对 SQL 语句进行解析，macro_rules 难以实现
    - 类函数宏定义形式：
        ```rust
        #[proc_macro]
        pub fn sql(input: TokenStream) -> TokenStream {
            ...
        }
        ```
- TODO
    - 过程宏：https://github.com/dtolnay/proc-macro-workshop、https://blog.turbo.fish/
    - 声明宏：https://veykril.github.io/tlborm/、https://zjp-cn.github.io/tlborm/

## 测试
### 断言
- assert_eq! 宏用于判断两个表达式的值是否相等
    - 不相等当前线程会直接 panic
    - 可以从第三个参数开始补充格式化输出额外信息
        ```rust
        assert_eq!(a, b, "额外信息：a = {}...", a);
        ```
- assert_ne! 宏类似，不过相等会 panic
- assert! 宏用于判断传入的布尔表达式是否为 true，为 false 的话会 panic
- debug_assert_eq! debug_assert_ne! debug_assert! 宏用法相同，但是只会在 Debug 模式下运行，例如 cargo run --release 就不会执行这些断言

### 编写测试
- rust 只会能 lib crate 进行测试，而无法对 bin crate 测试
- 单元测试
    - 定义一个 mod 并标记为 test：
        ```rust
        #[cfg(test)]
        mod tests {
            #[test]
            fn test1() {
                assert_eq!(2 + 2, 4);
            }
        }
        ```
    - panic 了则不通过
    - 对于测试函数添加一个 `#!rust #[should_panic]` 可以标记 panic 为期望结果，不 panic 则不通过
        - 可以使用 expected 参数来表示期望得到的 panic 字符串
            ```rust
            #[test]
            #[should_panic(expected="...")]
            fn test2() {
                ...
            }
            ```
    - 可以使用 Result 作为返回值，返回 Err 则不通过，可以这样来实现测试的链式调用，但 `#!rust #[should_panic]` 在此时将不可用
    - 使用 `#!rust #[ignore]` 来忽略当前测试
        - cargo test 时传入 --ignored 可以执行忽略的测试
- 集成测试
    - tests 目录用来专门存放集成测试，cargo 会从中寻找测试文件，在测试时都会运行
    - 每个文件内部不需要 `#!rust #[cfg(test)]` 以及不需要创建 mod
    - cargo test --test name 来仅测试 tests/name.rs 文件
    - tests 目录下的子目录中的文件不会被当作独立的包也不会有测试输出，可以通过子目录创建模块来存放测试时会使用但不希望被测试的代码
- cargo test
    - cargo test 执行所有测试
        - 单元测试、集成测试、文档测试
    - 使用 -- 附加参数
        - -- 后加 --test-threads=... 来指定进行测试的线程数
        - -- 后加 --show-output 来输出标准输出中内容
            - 默认情况下测试时如果通过则标准输出的内容不会显示出来
        - -- 后加 --ignored 来仅运行忽略的测试
        - -- 后加 --no-run 仅编译出测试二进制文件而不运行
    - 运行部分测试
        - cargo test name 来运行函数名里包含 name 的测试函数
            - 模块名也包含在其中，所以可以依此分模块进行测试
    - Cargo.toml 中加入 [dev-dependencies] 指定仅在 test 时会用到的依赖
    - cargo test 时会生成可运行测试的二进制文件，保存在 target/debug/deps/ 中
- 基准测试 benchmark
    - 官方 benchmark
        - 只能在非 stable 版本下使用，需要引入特性 `#!rust #![feature(test)]`
        - 和 test 一样写在 `#!rust #[cfg(test)]` 中，但不标记为 `#!rust #[test]` 而是 `#!rust #[bench]`
            ```rust
            #[bench]
            fn bench_test(b: &mut Bencher) {
                b.iter(|| ...);
            }
            ```
            - 初始化代码要写在 iter 之外，否则会多次循环
        - cargo test 会执行 benchmark 部分但不会有性能测试的输出结果
        - 通过 cargo bench 来执行 benchmark 代码，此时非 bench 的 test 会被 ignore
        - LLVM 会将没有副作用的函数直接优化删掉，可以使用 test::black_box 来包裹防止被优化，如
            ```rust
            b.iter(|| {
                test::black_box(func(test::black_box(arg)));
            })
            ```
    - 使用 criterion.rs（推荐）
        - 可以有更多的分析信息
        - 官方文档：https://bheisler.github.io/criterion.rs/book/getting_started.html