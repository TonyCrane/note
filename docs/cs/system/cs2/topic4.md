---
counter: True
comment: True
---

# 进程与线程

!!! abstract
    计算机系统 Ⅱ 第 10 至 12 周课程内容

## 进程
程序的执行过程，是操作系统进行资源分配和调度的基本单位。

### 进程的组成
- 程序代码，即 text 段
- 运行时 CPU 状态，包括 pc、寄存器等
- 多种内存空间（人为规定的，不是硬件概念）：
    - 栈（stack）：临时的数据：局部变量、函数调用参数、返回地址等
    - 堆（heap）：运行时动态分配的内存
    - data 段：全局变量
    - ……

通过 cat /proc/$pid/maps 可以查看进程的虚拟内存布局。

![](/assets/images/cs/system/cs2/topic4/img1_light.png#only-light)
![](/assets/images/cs/system/cs2/topic4/img1_dark.png#only-dark)

### 进程的状态
- 新建（new）：进程正在被创建
- 运行（running）：进程正在被 CPU 执行
- 等待（waiting/blocking）：进程正在等待某个事件的发生
- 就绪（ready）：进程已经准备好，等待被 CPU 执行
- 终止（terminated）：进程已经终止

![](/assets/images/cs/system/cs2/topic4/img2_light.png#only-light)
![](/assets/images/cs/system/cs2/topic4/img2_dark.png#only-dark)

### 进程控制块
进程控制块（Process Control Block，PCB）是操作系统为每一个进程维护的数据结构。

Linux 中通过 task_struct 结构体来存储，内容：

- `#!c pid_t pid`：进程号
- `#!c long state`：进程状态
- `#!c unsigned int time_slice`：时间片
- `#!c struct task_struct *parent`：父进程
- `#!c struct list_head children`：子进程
- `#!c struct files_struct *files`：打开的文件
- `#!c struct mm_struct *mm`：进程的内存空间
- ……
- pc、寄存器等

### 进程调度
- 操作系统内核的调度器（scheduler）来进行进程的调度，选择执行哪个进程
    - 此处暂时认为一个进程只包含一个线程
    - 实际上一个线程才是被调度的实体、最小单位
- 调度发生非常频繁，而且一定要快（为了提高系统的可响应性）
    - 被调度的进程不会意识到调度的发生
- 提高 CPU 利用率
    - 如果不调度的话，可能会出现某个进程一直在等待 I/O（CPU 闲置）
    - 此时可以调度到其他进程进行运行，提高 CPU 利用率
- 内核会维护几个队列进行调度：
    - 任务队列（job queue）：系统中所有进程
    - 就绪队列（ready queue）：就绪状态等待执行的进程
    - 设备队列（device queue）：等待 I/O 设备的进程

#### swap in & swap out
理论情况：

- 比如在进行进程调度（p0 切换到 p1）的时候物理内存不够用了
- 将 p0 用到的物理内存写入磁盘（swap 分区）
    - 这个操作就是 swap out
- 然后切换到 p1 进行执行，这时就有了充足的物理内存
- 再调度回 p0 时，需要将之前 swap out 的物理内存从磁盘读回来
    - 这个操作就是 swap in

如今实际的实现：

- 时刻 monitor 内存压力状况
    - 在系统空闲的时候进行 swap out
    - 而不是在内存已经要不够用的时候再 swap out
- 将比较少用的物理内存页（page）swap out
    - 粒度更细，不会将整个进程的物理内存都 swap out
- 在进程执行的时候发现要使用到了 swap out 出去的内存时才会 swap in

#### 进程分类
调度器会将进程分为两类：

- I/O-bound 进程：大部分时间都在进行 I/O 请求
- CPU-bound 进程：大部分时间都在执行 CPU 指令，进行计算

#### 上下文切换
- 在进行调度的时候，内核需要切换进程的上下文切换
    - 将旧进程的上下文保存到 PCB 中
    - 将新进程的上下文从 PCB 中恢复
- 上下文切换是有开销的
    - 在做的事情在用户态程序看来是没有意义的
    - 需要尽可能的缩短上下文切换的时间
    - 有硬件的支持可以加速上下文切换
        - 比如有的硬件中可以保存多套寄存器

![](/assets/images/cs/system/cs2/topic4/img3_light.png#only-light)
![](/assets/images/cs/system/cs2/topic4/img3_dark.png#only-dark)

### 进程创建
- 操作系统提供了一系列系统调用来进行进程的创建
- 系统中所有进程会形成一个进程树
- 系统在加载后会主动生成一个 pid 为 1 的主进程
    - 由 pid 0 的 idle 进程 fork 出来
    - 后面所有的进程都是它的子进程
- 三种资源共享形式：无共享（none）、选择性共享（subset）、完全共享（all）
- 父进程和子进程的地址空间
    - Linux：子进程复制一份父进程的地址空间
    - Windows：子进程有新加载的程序
- 父进程和子进程的执行
    - 创建之后，父进程和子进程会同时执行（作为独立被调度的实体）
    - 父进程可以等待子进程结束后才结束
- UNIX/Linux 创建进程相关的系统调用
    - fork：创建一个子进程
    - exec：执行一个程序（覆盖原来的地址空间）
    - wait：等待子进程结束

### 进程终止
- 进程结束（exit）后需要释放掉资源（例如 PCB）
- 父进程可以通过 wait 等待子进程结束并获取子进程的返回值
- 父进程也可以通过 abort 来终止子进程

### 孤儿进程与僵尸进程
- Linux 允许父进程先于子进程结束
    - 而一些操作系统不允许这样，父进程结束后会强制杀死所有子进程
    - 这一设计产生了孤儿进程
- 孤儿进程（Orphaned Process）
    - 父进程没有等待子进程结束，而先于子进程结束
    - 子进程会被 init 进程（pid 1）接管
        - 例如 systemd 会通过 wait 来等待孤儿进程结束
- 僵尸进程（Zombie Process）
    - 子进程结束了，但是父进程没有 wait
    - 这时子进程的相关资源不会被释放
    - 只有手动 kill 掉父进程才会释放
        - 即让僵尸进程变为孤儿进程，从而被 init 进程接管、释放
        - kill 掉僵尸进程无效，因为进程已经死了

### Android Zygote 进程
- 目的是提高响应性，提高应用启动速度
- 系统启动后 pid 1 init 进程会 fork 出一个 Zygote 进程
- Zygote 中会加载一些系统库、运行时
- 在其他应用启动的时候会从 Zygote 进程 fork 出子进程
    - 子进程会复制 Zygote 进程完整的地址空间
    - 不需要进行额外的加载库操作，提高启动速度
- 安全问题
    - Zygote fork 出来的进程内存布局相同

### 进程间通信
- 独立进程（independent process）：不会影响其他进程执行，也不会被其他进程影响
- 协作进程（cooperating process）：可以/需要和其他进程互相影响（包括数据共享）
    - 这样的进程需要进程间通信（Inter-Process Communication，IPC）
- 有两种 IPC 的模型
    - 共享内存（Shared Memory）
    - 消息传递（Message Passing）

#### POSIX 共享内存
- 通过 `#!c shm_open(name, O_CREAT | O_RDWR, 0666)` 创建共享内存
    - name 是共享内存的名字
    - O_CREAT 表示如果不存在则创建
    - O_RDWR 表示可读可写
    - 0666 表示权限
    - 返回一个文件描述符（shm_fd）
- 通过 `#!c ftruncate(shm_fd, size)` 设置共享内存的大小
- 通过 `#!c mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0)` 将共享内存映射到进程的地址空间
    - PROT_READ 表示可读、PROT_WRITE 表示可写
    - 返回一个指向共享内存的指针（shm_ptr）
    - 之后便可以通过 shm_ptr 来读写共享内存
    - 通过 mmap 进行操作与通过 read、write 进行读写的好处：
        - mmap 后可以直接操作内存
        - read、write 还会经过系统调用

## 线程
为什么需要线程：

- 进程之间资源是隔离的，资源共享困难（都要通过 IPC）
- 同一进程里的不同线程的资源是共享的，资源共享高效且易用
- 线程是可以被调度的实体、最小单位
    - 因此线程可以独立运行，又可以共享数据
- 线程的创建比进程更轻量
- 线程优点：
    - 可响应性更高
    - 资源共享更方便更高效（不需要通过 IPC、系统调用）
    - 更经济（线程更轻量）
    - 并行性更强（多核 CPU 可以同时运行多个线程）
 
什么是线程：

- 独立的指令序列，可以被内核单独调度
- 共享与不共享的资源：
    - 共享进程的 code、data、heap、files
    - 每个线程有自己独立的 stack、registers、pc、thread-specific data
        - 保留每个线程独立的执行的环境来支持进行调度
        - 栈不共享，但是不隔离（即可以通过地址解引用来获取其他线程栈上的值）

### 并发与并行
- 并发（Concurrency）：
    - 强调将一个程序组织成逻辑上多个不同执行的单元
    - 使并行执行变得可能
    - 更强调程序的组织结构
- 并行（Parallelism）：
    - 多个执行单元可以在同一时刻（物理）同时执行
    - 更强调程序的执行方式
- 设计代码的时候要考虑的是提高并发性
    - 并发提供了使程序可能并行执行的结构
    - 并行是执行时做的，只有多核才可能并行执行

### 线程的实现
- 用户态线程（User-Level Threads）
    - 通过线程库：POSIX Pthreads、Win32 threads、Java threads、……
- 内核态线程（Kernel-Level Threads）
    - **内核态线程才是被调度的实体**
    - 如果操作系统实现了内核态线程，才支持用户态线程单独调度
        - 系统才可以感知用户态线程
        - 系统会为每个用户态线程绑定到一个内核线程上
        - 系统会以内核态线程为粒度进行调度，实现用户态线程的单独调度
    - 不会影响用户态线程库的使用，但只有实现了内核态线程的概念，才可以实现线程的单独调度
    - 操作系统里会维护一个单独的线程表（thread table）来跟踪系统中的所有线程（而不是通过每个进程中的线程表）

如果没有内核态线程，也就是说操作系统没有实现线程的概念，那么用户态线程仍然可以通过线程库正常创建，不过只能并发而不能并行执行（因为此时系统的调度粒度是进程为单位，不会单独调度进程中的各个用户态线程）。

如今的操作系统一定都是支持内核态线程的。

#### 用户线程与内核线程关系
- 多对一（many-to-one）
    - 多个用户态线程绑定到同一个内核态线程上
    - 当系统调度到这个内核线程时，返回到对应的用户态线程调度器上选择运行哪一个用户线程
    - 当一组内的一个用户态线程进行系统调用的时候，其它用户态线程也不会得到运行机会
        - 因为系统从当前内核态线程调度走了
        - 系统不会意识到内核态线程中有多个用户态线程等待执行、调度
    - 在如今的系统中已经不存在
- 一对一（one-to-one）
    - 一个用户态线程绑定到一个内核态线程上
    - 每创建一个用户态线程都会创建一个对应的内核态线程
    - 一个线程被 block 的时候，其它线程仍然可以运行
    - 多线程可以并行运行在多处理器上
    - 总线程数量可能会受限
    - Linux、Windows NT/XP/2000
- 多对多（many-to-many）
    - 多个用户态线程绑定到多个内核态线程
    - 可以创建任意多的用户态线程
    - Windows NT/2000 with ThreadFiber package
- two level 模型
    - 同时支持 many-to-many 和 one-to-one

### 线程相关的问题
#### fork 和 exec 系统调用的语义
- 每一个 fork 都是从一个进程中的单个线程调用的
    - 存在两种实现方式：
        - duplicate 当前线程作为一个进程
        - duplicate 当前进程的所有线程作为一个进程
    - 具体如何实现看系统
        - 有些 UNIX 系统保留了两种 fork 的实现方式
        - Linux 默认情况下会 duplicate 所有线程
- exec 是用新的程序来替代原来的程序，会替代所有线程
- fork 和 exec 经常一起使用（先 fork，然后 exec）
    - 如果系统中实现了多种 fork 的语义：
        - 如果 fork 后立即 exec，则会只 duplicate 当前线程（否则浪费了）
        - 否则会 duplicate 所有线程

#### 信号处理
- 信号（Signals）是 UNIX 系统中在出现一些特定事件的时候，向进程发送的通知
- 可以在用户程序中注册信号处理函数 callback
    - 例如，程序中出现了非法地址访问，系统会发送一个 SIGSEGV 信号（Segmentation Violation）
        - 如果程序中注册了针对 SIGSEGV 的处理函数，则会调用这个函数
        - 否则，程序会执行默认的信号处理函数，也就是段错误而被终止
- 信号可能是同步的或异步的
    - 同步信号，例如异常，会在当前线程中被处理
    - 异步信号，例如 I/O，则在多线程情况下有歧义
- 多线程异步信号发送的几种选择：
    - 发送到信号产生的线程
    - 发送到当前进程中的所有线程
    - 发送到当前进程中的某一个或某几个特定的线程
    - 发送到进程中指定接收所有信号的一个特定线程

#### 终止线程的处理方式
- Thread Cancellation 即在一个线程结束之前强制终止
- 线程可能会被立即终止，也可能延迟终止
- 立即终止（asynchronous cancellation）
    - 线程会被立即终止
    - 但如果目标线程执行到了关键部分（critical section）时可能会造成访问资源的紊乱
        - 例如线程 A、B 执行同一段代码，代码中有一部分要访问某一处资源，这里就称为 critical section
        - 在同一时刻，只能有一个线程执行 critical section，访问资源
        - 如果线程 A 正在访问资源，那么 B 此时会被 block 住
        - 如果此时终止线程 A，则有可能会造成资源访问紊乱
- 延迟终止（deferred cancellation）
    - 允许线程周期性检查自己是否可以结束

#### thread-specific data
- Thread-Local Storage（TLS）允许每个线程拥有自己的数据拷贝
- 与局部变量的区别
    - 局部变量只在当前的作用域中可见
    - TLS 在整个线程运行过程中，所有函数调用中都可见
- 类似于 static data，不过每个线程拥有的都是独立的数据
- 使用 TLS
    - 通过 pthread：
        - 在每个线程执行的函数中可以调用 pthread_setspecific() 来设置 TLS，pthread_getspecific() 来获取 TLS
        ```c 
        pthread_key_t key;

        void *exec_in_thread(void *args_in) {
            int *tl = malloc(sizeof(int));
            *tl = 1;
            pthread_setspecific(key, tl);
        }
        ```
    - 通过 __thread 关键字
        - 将变量声明为 __thread，则这个变量就是 TLS
        ```c 
        __thread int x = 3;
        
        void *exec_in_thread(void *args_in) {
            x += 1;
            printf("%d\n", x);
        }
        ```

### LWP
- 此处的 LWP 指的是一个概念，和后面提到的 LWP 不是同一个东西
- Lightweight process（LWP）是在 many-to-many 和 two level 两种模型中用户态线程和内核态线程的中间层
- 对于用户态线程库，LWP 充当虚拟处理器（virtual processors）的角色，来调度用户态线程
- 一个 LWP 会被绑定到一个内核态线程上
- upcalls：当内核要调度线程的时候，会通过 upcall 来通知线程库（类似 signal）

### Linux task
- Linux 中除了 fork 以外还有一个 clone 系统调用
- clone 可以创建一个新的实体，接收一些 flag 来指定资源共享情况
    - CLONE_FS、CLONE_VM、CLONE_FILES、CLONE_SIGHAND 分别表示是否共享文件系统、虚拟内存、文件描述符、信号处理
    - 如果四个 flag 都设置了（完全共享），那么就相当于创建了一个线程
    - 如果没有设置任何 flag（完全不共享），那么就相当于创建了一个进程（fork）
    - 部分设置，创建了一个新的 task
- Linux 内核并不区分线程和进程，都将其看作 task
- Linux 场景下，内核线程被称为 LWP（轻量级进程），也称为 kernel scheduling entity（内核调度实体）

### Pthread 线程库
- 一套 POSIX（Portable Operating System Interface for uniX）标准的 API 用于线程的创建、管理、同步等
- 在 UNIX / 类 UNIX 系统中常用
- Pthread 是一套线程行为的标准，具体实现由库开发者决定

### Linux 对于线程的实现
- Linux 中用户线程是服从 POSIX 标准的
- Linux 中有两个单独的执行 space
    - user space：用户态线程是通过 pthread 库来创建的
    - kernel space
        - 内核线程都是 lightweight process（LWP）
        - 一个 LWP 是一个单独被调度的单元

#### Linux LWP
- 通过 gettid() API 可以获取当前 LWP 的 ID
    - 与 pthread_self() 不同
- 通过 ps -efL 可以查看系统中的所有 LWP 及编号
- 每一个用户线程都会 1:1 映射到一个 LWP 上
- 一个用户态的进程是一系列有共同 group ID 的 LWP 的集合
    - 分组可以让内核进行资源的共享等
- Linux 通过 clone 系统调用来创建 LWP
    ```c 
    int clone(int (*fn)(void *), void *child_stack, int flags, void *arg);
    ```
    - clone 比 fork 更通用，fork 可以通过 clone 来实现