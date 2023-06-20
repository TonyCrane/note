---
counter: True
comment: True
---

# C++ 面向对象程序设计

!!! abstract
    浙江大学 “面向对象程序设计” 课程相关知识笔记，语言是 C++。这里就简单记点我觉得额外需要注意的内容，不会很全面，很多同学/学长已经做了很丰富的笔记，我列在下面了，也就不重复劳动了。

    参考

    - 图灵班课程学习指南：[面向对象程序设计](https://zju-turing.github.io/TuringCourses/major_basic/object_oriented_programming/)

!!! example "更多更好的参考笔记"
    - [xyx 的众多 C++ 笔记](https://xuan-insr.github.io/cpp/cpp_restart/)
    - [HobbitQia 的 oop 笔记](https://note.hobbitqia.cc/OOP/oop1/)
    - [修佬的 oop 笔记（语雀）](https://www.yuque.com/isshikixiu/codes/wk_oop)
    - [fcrgg 的 oop 笔记（pdf）](https://github.com/RyanFcr/ZJU_Course/blob/main/%E5%A4%A7%E4%BA%8C%E6%98%A5%E5%A4%8F/%E9%9D%A2%E5%90%91%E5%AF%B9%E8%B1%A1%E7%A8%8B%E5%BA%8F%E8%AE%BE%E8%AE%A1OOP/OOP.pdf)
    - [贺老师的 C/C++ 沉思录（知乎专栏）](https://www.zhihu.com/column/c_1561843704159232000)

## 关于变量
### 引用
- 引用本质上是指针
- `#!cpp typename &ref = var;` 创建 binding 关系，ref 是 var 的引用
- 引用必须在声明时初始化，且不能再改变绑定的变量
- 引用可以作为函数参数，这样可以修改参数的值
    - 一般建议用常量引用作为参数替代值传递，这样可以避免拷贝
- 引用不存在引用，也不存在指针
    - 但是存在指针的引用
    - 即 `int&*` 非法 `int*&` 合法

### 常量
- 在编译时期对数据的保护，防止变量被修改
- `#!cpp const typename var = val;` 声明常量
- `#!cpp char * const p` 表示指针 p 指向的位置不能改变，但是指向的内容（一个 char）可以改变
- `#!cpp const char *p` 表示指针 p 指向的内容不能改变，但是指向的位置可以改变
    - `#!cpp char const *p` 同理等价
- `#!cpp const char * const p` p 指向的位置和内容都不能修改

### 动态内存
- 使用 new 分配，创建对象，返回指针
- `#!cpp T *p = new T[N]` 分配 N 个 T 类型的对象，返回指向第一个对象的指针
- `#!cpp delete p` 释放 p 指向的内存
    - p 本身不会变为 NULL
- `#!cpp delete[] p` 释放 p 指向的内存
    - new 的时候会记录一个表，地址和大小，delete 的时候会根据这个表释放
    - 如果分配的是数组的话，则 delete 的时候 [] 不能省

## 关于函数
### inline 函数
- 编译时展开代码（类似宏），用于优化，减少函数调用的开销
- inline 函数的定义也相当于声明，可以在头文件中定义
- 到底是否会 inline 由编译器决定
- inline 函数不能递归
- 一般短小且经常调用的函数可以声明为 inline

## 关于类

- C++ 中 class 和 struct 并无本质区别，只是默认的访问权限不同（class 默认 private，struct 默认 public）
- :: 称为域解析器（resolver），前面什么都不带则解析到自由变量/函数（即全局作用域内）
- 成员函数直接在类内部定义的话默认为 inline（不推荐）
- 权限有三种：
    - public：公有
    - private：私有（只有同类可以访问）
        - 注意边界是类不是对象，成员函数中可以访问同一类的其他对象的私有成员
    - protected：保护（只有同类和子类可以访问）

### 构造函数（C'tor）
- default C'tor 指不带参数的 C'tor 而不是编译器生成的 C'tor
- 在没有定义任何 C'tor 的情况下，编译器会生成一个 auto default C'tor
- 只要定义了 C'tor 则不会自动生成，即使不存在 default C'tor
- 成员变量初始化顺序
    - 先是构造函数的初始化列表
        - 包括成员变量声明中直接定义赋值（C++11，本质是初始化列表的语法糖）
        - 内部顺序按照成员变量声明顺序，而不是初始化列表中的顺序
    - 然后再执行构造函数的函数体
- 拷贝构造函数
    - 声明为 `#!cpp ClassName(const ClassName &obj);`
    - 在发生拷贝时会调用，比如 `#!cpp ClassName obj2 = obj1;`、函数调用（不是引用/指针的情况下）、函数返回（不是引用的情况下）

### 析构函数（D'tor）
- 析构函数不能有任何参数，也没有返回值
- 在对象被销毁（移出作用域）时自动调用
- 析构函数是 virtual 的

### 静态成员变量/函数
```cpp
class A {
public:
    static int a;
    int b;
};

int A::a = 0;
A obj;
```

- 静态成员变量属于类，而不是对象
- godbolt 编译一下可以看到静态成员变量实际上是存储在单独的区域的
- A::a 和 obj.a 都会访问到同一位置
- 必须要在类外部初始化 `#!cpp type ClassName::var = value;`，不然链接会报错
- 静态成员函数不包含 this 指针

### 常量成员变量/函数
- 常量成员变量必须在初始化列表中初始化
    ```cpp
    class A {
        const int a;
    public:
        A(int a) : a(a) {}
    };
    ```
    - 或者 `#!cpp const int a = ...;`，但这样所有实例的 a 都是一样的
- 常量成员函数不能修改成员变量值（相当于 this 指针指向的内容是 const 的）
    ```cpp
    class A {
        int a;
    public:
        int getA() const {
            return a;
        }
        void setA(int _a) const {
            a = _a; // error
        }
    };
    ```

### 继承
```cpp
class Base {
    ...
}

class Derived : (public/private/protected) Base {
    ...
}
```

- 继承的访问权限
    - public 继承：public->public，protected->protected，private->不可访问
    - protected 继承：public->protected，protected->protected，private->不可访问
    - private 继承：public->private，protected->private，private->不可访问
- 基类的 private 变量会被隐藏，但仍然存在
- C'tor、D'tor、重载运算符、友元不会被继承
- 可以多继承
- 初始化顺序为：
    - 依次初始化基类
    - 根据声明顺序初始化成员变量（以及初始化列表）
    - 执行构造函数函数体

### 友元
- 打破访问权限，更 "C-like"
- 类中声明友元可以让外部的函数/外部类的所有成员函数访问当前类的私有成员
- 友元关系不能被继承

### 多态
- upcasting：向上造型，子类指针/引用指向父类对象

#### 虚函数
- 一个类中有成员函数前有 virtual 时，则该类的存储开头第一块地址汇存放一个指向该类虚函数表的指针
- 虚函数表中存放若干指针，指向该类的若干虚函数
- 虚函数被继承后仍然是虚函数，可以省略 virtual，但仍为虚函数（建议还是带上）
- 如果一个类中存在没有实现的虚函数（纯虚函数），则该类为抽象类，无法实例化
    - 并非所有包含虚函数的类都是抽象类
    - 但抽象类可以有引用和指针
- 构造函数不能是虚函数（此时还没有虚函数表）
- 析构函数一定是虚函数
- 虚函数的作用会在静态绑定/动态绑定的时候体现出来

#### 静态绑定/动态绑定

- 静态绑定（static binding / early binding）：编译时就能明确确定调用的函数
- 动态绑定（dynamic binding / late binding）
    - 出现多态，编译器并不知道调用的是哪个类的方法
    - 发生在运行时刻
    - 只有存在 virtual 且通过指针访问时，才会发生动态绑定
- 本质上要看编译器能否确定，而不是是否是 virtual，如果能确定，即使是 virtual 也会发生静态绑定
- 例：
    ```cpp
    class Shape {
    public:
        void render() { cout << "Shape" << endl; }
    };

    class Circle : public Shape {
    public:
        void render() { cout << "Circle" << endl; }
    };

    void render(Shape *p) {
        p->render(); // p 是多态变量
    }

    int main() {
        Shape s; Circle c;
        s.render(); // 静态绑定 输出 Shape
        c.render(); // 静态绑定 输出 Circle
        render(&s); // 静态绑定 输出 Shape
        render(&c); // 静态绑定 输出 Shape
    }
    ```
    - 如果给两个成员 render 加上 virtual，则后两个调用 render 函数的会发生动态绑定，第二次会输出 Circle

#### 菱形继承
- 由于 C++ 支持多继承，所以可能会有菱形继承的情况出现
    - 即 B 和 C 都继承自 A，D 继承自 B 和 C
- 会导致 D 中存在两份 A 的成员变量，不显式指定会报错
    ```cpp
    class A { public: int a; };
    class B : public A { public: int b; };
    class C : public A { public: int c; };
    class D : public B, public C {
    public:
        void func(int _a, int _b, int _c) {
            a = _a; // error: request for member 'a' is ambiguous
            B::a = _a; // ok
            C::a = _a; // ok
            b = _b; c = _c; // ok
        }
    };
    ```
- 另一种解决方法是使用虚继承，让 B 和 C 都虚继承自 A，这样 D 中就只保留一份 a 变量，A 被称为虚基类
    ```cpp
    class A { public: int a; };
    class B : virtual public A { public: int b; };
    class C : virtual public A { public: int c; };
    class D : public B, public C {
    public:
        void func(int _a, int _b, int _c) {
            a = _a; b = _b; c = _c; // all ok
        }
    };
    ```
- 因此并不推荐使用多继承

## 关于重载
### 函数重载
- 函数名相同，参数列表不同
- 返回值类型不同不算重载

### 运算符重载
- 只能重载 C++ 已有运算符
    - 可以重载
        ```cpp
        + - * / % ^ & | ~
        = < > += -= *= /= %= ^= &= |=
        << >> >>= <<= == != <= >=
        ! && || ++ -- , ->* -> () []
        new new[] delete delete[]
        ```
    - 不能重载
        ```cpp
        . .* :: ?: sizeof typeid
        static_cast dynamic_cast const_cast reinterpret_cast
        ```
- 不能改变运算符的优先级
- 不能改变运算符的结合性
- 不能创建新的运算符
- 不能改变运算符的操作数个数

重载形式：

- 成员运算符重载
    - 双目运算符左侧的操作数是对象本身，右侧的操作数是函数的参数
- 全局运算符重载
    - 如果要访问私有成员的话要设置为友元
- 重载策略：
    - 一元运算符应该是成员函数
    - `#!cpp = () [] -> ->*` 必须是成员函数
    - 其他二元运算符应该是全局函数

运算符类型：

- `#!cpp + - * / % ^ & | ~`
    ```cpp
    const T operator <op> (const T &l, const T &r);
    ```
- `#!cpp = < > += -= *= /= %= ^= &= |= <<= >>=`
    ```cpp
    T &operator <op> (const T &l, const T &r);
    ```
- `#!cpp ! && || < <= == >= >`
    ```cpp
    bool operator <op> (const T &l, const T &r);
    ```
- `#!cpp []`
    ```cpp
    T &operator [] (int index); // 也可以是其他类型而非 int
    ```
- `#!cpp ++ --`
    ```cpp
    const T &operator ++ ();   // ++x 前置
    const T operator ++ (int); // x++ 后置（int 无用）
    ```

流运算符重载：

- 创建某个类的输入输出
    ```cpp
    ostream &operator << (ostream &out, const T &obj);
    istream &operator >> (istream &in, T &obj);
    ```
    - 需要的情况下要设置友元
- 创建 manipulators（和重载运算符无关）
    ```cpp
    ostream& tab(ostream& out) {
        return out << '\t';
    }
    cout << "a" << tab << "b";
    ```

## 其他部分
### 模板
- 定义函数模板
    ```cpp
    template <class T>
    void swap(T&x, T&y) { ... }
    ```
    - 调用时可以显式指定参数 T：`swap<int>(a, b);`
    - 可以 `#!cpp template <class T, class U>` 指定多个类型
- 函数模板相当于声明，编译期会根据实际使用的类型生成模板函数
    - 类型精确匹配，不可以有隐式转换
    - 函数模板需要放在头文件中
- 同类型函数模板和普通函数可以同时存在
    - 优先匹配普通函数
    - 普通函数可以进行参数隐式转换，函数模板只能精确匹配
- 类模板类似
    - 需要注意成员函数在外部定义时要加上 `#!cpp template <class T>`
        ```cpp
        template <class T>
        class A {
        public:
            void func(T x) { ... }
        };
        template <class T>
        void A<T>::func(T x) { ... }
        ```
- 模板参数可以是常量表达式
    ```cpp
    template <class T, int bounds = 100>
    class FixedVector {
        T elements[bounds];
    }
    ```
    - 需要显式指定参数（否则使用默认）
- 关于继承
    - 类模板可以继承自普通类
        ```cpp
        template <class T>
        class A: public B { ... }
        ```
    - 类模板可以继承自类模板
        ```cpp
        template <class T>
        class A: public B<T> { ... }
        ```
    - 普通类可以继承自模版类（不是类模板）
        ```cpp
        class A: public B<int> {...}
        ```
    
### 异常
- 通过 throw 抛出异常，可以 throw 任何东西
- 一般 throw 异常类（即带有异常信息的一个普通的类）实例
- try-catch
    ```cpp
    try { ... }
    catch (SomeError& e) { ... }
    catch (AnotherError) { ... } // 忽略错误具体内容
    catch (...) { ... } // 其他全部异常用 ... 表示
    ```
    - catch 块中可以 `#!cpp throw;` 来将当前处理的异常重新抛出去，实现异常的传递
- new 的异常
    - new 在分配失败的时候不会像 malloc 一样返回 0
    - 分配失败会抛出 bad_alloc 异常
- 标准库异常
    - bad_alloc bad_cast bad_typeid bad_exception
    - runtime_error: overflow_error range_error
    - logic_error: domain_error length_error out_of_range invalid_argument
- 函数的异常声明
    - 声明当前函数可能会抛出哪些异常
        ```cpp
        void func(int a) : throw (SomeError, AnotherError) { ... }
        ```
        - `#!cpp throw ()` 不抛出任何异常，C++11 写为 noexcept
    - 编译期不会检查
    - 运行时抛出了非预期的异常时会抛出 unexpected 异常
        - unexpected 异常会调用 std::unexpected() 函数
        - 可以通过 std::set_unexpected(handler) 来将一个函数设置为 unexpected 处理函数
- 构造函数中的异常
    - 构造函数中可以抛出异常，使对象非完全构造，析构时不会调用析构函数，throw 前清理分配的资源
    - 可能会出现内存泄漏，注意 delete
    - 推荐二阶段构造
        - 构造函数中只进行一些简单的复制和初始化（不分配任何资源）
        - 可能会抛出异常的工作在另外单独的函数 init 中初始化
- 析构函数异常
    - 析构函数不推荐抛出异常
    - 必须在析构函数内消化所有异常，否则会调用 terminate 函数终止程序
- 异常与继承
    - 异常派生类能被基类捕获，要先捕获派生类再捕获基类
        ```cpp
        class A { ... };
        class B: public A { ... };
        try { ... }
        catch (B& e) { ... } // 注意使用引用
        catch (A& e) { ... }
        ```
- 未捕获的异常
    - 未捕获的异常会调用 std::terminate 函数终止程序
    - 可以通过 std::set_terminate(handler) 来将一个函数设置为 terminate 处理函数

### 流
- 分类
    - 通用：istream ostream <iostream\>
    - 文件：ifstream ofstream <fstream\>
    - 字符串：istringstream ostringstream <sstream\>
        - C 字符串：istrstream ostrstream <strstream\>
- 读：extractor >>
- 写：inserter <<
- 改变流状态：manipulators
- 预定义流：cin cout cerr clog
- 自定义 extractor inserter
    ```cpp
    istream& operator >> (istream& in, T& obj) {
        ...
        return in;
    }
    ostream& operator << (ostream& out, const T& obj) {
        ...
        return out;
    }
    ```
- istream 其他运算符
    - `#!cpp while ((ch = cin.get()) != EOF)`
    - `#!cpp istream& get(char& ch)`
    - `#!cpp istream& get(char *buf, int limit, char delim = '\n')`
    - `#!cpp istream& getline(char *buf, int limit, char delim = '\n')`
    - `#!cpp istream& ignore(int limit = 1, int delim = EOF)`
    - `#!cpp int gcount()` 返回最后一次读取的字符数
    - `#!cpp istream& putback(char ch)` 将字符放回流中
    - `#!cpp istream& peek()` 返回下一个字符但不从流中取出
- ostream 其他运算符
    - `#!cpp ostream& put(char ch)`
    - `#!cpp ostream& write(const char *buf, int size)`
    - `#!cpp ostream& flush()` 刷新缓冲区
- manipulators
    - dec hex oct，设置进制，I/O
    - setw(n) setfill(c)，设置宽度和填充字符，I/O
    - endl flush，换行和刷新缓冲区，O
    - setbase(n) setprecision(n)，设置进制和精度，O
    - ws，跳过空白字符，I
    - setiosflags(...) resetiosflags(...)，设置和重置 I/O 格式标志，I/O
        - ios::left ios::right，左右对齐
        - ios::showpos ios::showpoint ios::showbase，显示正负号、小数点、进制前缀
        - ios::uppercase ios::lowercase，大写小写
        - ios::scientific ios::fixed，科学计数法、定点表示法
        - ios::internal，数值在填充字符之间
        - ios::skipws，跳过空白字符
        - ios::unitbuf，每次输出后刷新缓冲区
        - 用二进制或叠加 flag
        - 也可以调用成员函数 setf 和 unsetf 来设置
- 流状态
    - 文件尾 eof，格式错误 fail，数据丢失 bad，其余 good
    - clear() 清除流状态到 good
    - good() eof() fail() bad()，判断流状态
- 文件流
    - 打开模式 flag
        - ios::app 附加，ios::ate 定位到文件尾，ios::trunc 清空文件
        - ios::in 读，ios::out 写，ios::binary 二进制
        - ios::nocreate 不存在时不创建，ios::noreplace 存在时不覆盖
    - 用法
        ```cpp
        ofstream fout("file.txt", ios::out | ios::app);
        fout << "Hello" << endl;
        fout.close();
        ifstream fin("file.txt");
        ifstream input;
        input.open("file.txt", ios::in);
        ```
- stream buffer
    - rdbuf() 返回流的 streambuf 对象