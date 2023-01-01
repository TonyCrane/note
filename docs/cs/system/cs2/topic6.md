---
counter: True
comment: True
---

# 进程同步

!!! abstract
    计算机系统 Ⅱ 第 14 至 15 周课程内容

## 背景
- 进程是可以并发执行的
    - 在这里也不区分进程和线程
- 进程在执行的时候可能会被随时打断
    - 并发访问共享的资源可能会导致数据不一致性（data inconsistency）

比如，进程中创建了两个线程，分别对共享的全局变量 counter 进行循环 + 1：
```c
static volatile int counter = 0;
void *mythread(void *arg) {
    printf("%s: begin\n", (char*)arg);
    int i;
    for (i = 0; i < 1e7; i++) {
        counter = counter + 1;
    }
    printf("%s: done\n", (char*)arg);
    return NULL;
}
```
最后在两个线程结束的时候，counter 值会小于 2e7。原因：

- `#!c counter = counter + 1` 在 C 语言里是一条语句
- 但是在汇编层面并不是**原子操作**，有三条语句来完成这一操作：
    ```asm
    mov eax, <addr of counter>
    add eax, 1
    mov <addr of counter> eax
    ```
    - 分别进行 读、加一、写
- 如果一个线程在写之前被打断然后执行另一个线程了，会产生如下问题：
    ```text
        Thread 1      OS      Thread 2
    ---------------- ---- ----------------
      read (eax=50)
        +1 (eax=51) 
                      ->
                            read (eax=50)
                              +1 (eax=51)
                           write (51)
                      <-
     write (51)
    ```
    - 两个线程都读到了 50，然后都加了一，最后都写回了 51
    - 虽然两个线程都被执行了一次，但最后 counter 的值只加了 1

## 条件竞争
- 几个进程并发地访问、修改同一个共享变量，其结果取决于访问的顺序，这种情况称为**条件竞争**（race condition）
- 如上就是一个条件竞争的例子
- 内核中也会发生条件竞争
    - 例如两个进程都在 fork 子进程，请求新的进程号
    - 进程号由内核全局变量 next_available_pid 维护
    - 内核并发处理两个 fork 请求时，可能会导致两个进程得到相同的进程号

### Critical Section
- 每个进程都有一个**临界区**（critical section，CS）
    - 例如访问共享变量
- 在同一时刻，只有一个进程可以处在 critical section
- 在进入 critical section 之前需要请求进入 CS 的权限，这部分代码称为 entry section
- 退出 CS 后释放权限，这部分代码称为 exit section
- 剩下的部分称为 remainder section
- 进程 p 的一个通用结构：
    ```c 
    do {
        entry section;
        critical section;
        exit section;
        remainder section;
    } while (true);
    ```

### 解决 CS 问题的三个条件
- Mutual Exclusion（互斥，ME）
    - 任意时刻只有一个进程在 CS 中
- Progress
    - 如果没有进程在 CS 且有进程需进入 CS，那么只有那么不在 remainder section 内执行的进程可参加选择，以确定谁能下一个进入 CS，且这种选择不能无限推迟
- Bounded Waiting
    - 从一个进程做出进入 CS 的请求，直到该请求允许为止，其他进程允许进入其 CS 的次数有上限
    - 防止了饥饿（starvation）

### Peterson 算法
- Peterson 算法解决了两个进程的同步问题
- 其假设 load 和 store 是原子性（atomic）的
    - 原子性即不可分割，中途不能被打断
- 两个进程共享两个变量：
    - `#!c int turn`：标记当前正在 CS 中的进程
    - `#!c bool flag[2]`：标记进程是否想进入 CS
- Process 0:
    ```c
    do {
        flag[0] = true;
        turn = 1;
        while (flag[1] && turn == 1);
        // critical section
        flag[0] = false;
        // remainder section
    } while (true);
    ```
- Process 1:
    ```c
    do {
        flag[1] = true;
        turn = 0;
        while (flag[0] && turn == 0);
        // critical section
        flag[1] = false;
        // remainder section
    } while (true);
    ```
- 在现代体系结构乱序执行下不能保证正常工作


### 同步问题的硬件支持
- 单处理器：可以通过禁止中断来实现
    - 即非抢占式内核
    - 在多处理器中效率低
- 解决方案：
    - 内存屏障 Memory Barrier
    - 硬件指令
        - test-and-set 指令
        - compare-and-swap 指令
    - 原子变量 Atomic Variable

#### 内存屏障
- 两种内存模型
    - Strongly ordered：一个处理器对内存的修改对于其它处理器立即可见
    - Weakly ordered：一个处理器对内存的修改对于其它处理器不一定立即可见
- 内存屏障（memory barrier）是一个可以强制一个处理器对内存的修改传播到所有处理器的指令

#### 硬件指令
- test-and-set 指令
    - 语义为：
        ```c 
        bool test_set(bool *target) {
            bool rv = *target;
            *target = true;
            return rv;
        }
        ```
    - 整体是一个原子操作
    - 用于实现 Peterson 算法
        ```c
        do {
            while (test_set(&lock)); // busy wait
            // critical section
            lock = false;
            // remainder section
        } while (true);
        ```
        - 这种解法不满足 Bounded Waiting，无法保证 waiting 的一定被执行（取决于调度）
    - 满足 Bounded Waiting 的解法：
        ```c
        do {
            waiting[i] = true;
            while (waiting[i] && test_set(&lock));
            waiting[i] = false;
            // critical section
            j = (j + 1) & n;
            while ((j != i) && !waiting[j])
                j = (j + 1) % n;
            if (j == i) lock = false;
            else waiting[j] = false;
            // remainder section
        } while (true);
        ```
- compare-and-swap 指令
    - 语义为：
        ```c
        bool compare_and_swap(int *ptr, int expected, int new_value) {
            int rv = *ptr;
            if (rv == expected) {
                *ptr = new_value;
            }
            return rv;
        }
        ```
    - 整体是一个原子操作
    - 使用 compare-and-swap 指令的解法
        ```c
        do {
            while (compare_and_swap(&lock, 0, 1) != 0);
            // critical section
            lock = 0;
            // remainder section
        } while (true);
        ```

#### 原子变量
- 提供了对于整型、浮点型这种基础数据类型的原子性修改
- 例如 `#!c increment(&sequence)` 来原子性增加 `sequence` 的值
- 使用 compare-and-swap 的实现：
    ```c
    void increment(int *sequence) {
        int temp;
        do {
            temp = *sequence;
        } while (compare_and_swap(sequence, temp, temp + 1) != temp);
    }
    ```

### 互斥锁
- 前面的方法在应用程序中编写太复杂
- OS 设计者通过软件工具来解决 CS 问题，最简单的就是互斥锁（mutex lock）
- 通过先 acquire() 锁，然后执行 CS，再 release() 锁来保护 CS
- acquire() 和 release() 必须是原子的
    - 通过硬件原子指令来实现
- 自旋锁（spin lock）实现
    ```c 
    void acquire() {
        while (!available); // busy wait
        available = false;
    }
    void release() {
        available = true;
    }
    ```
    - 通过忙等待（busy waiting）来实现
    - 但是忙等待会影响效率（CPU 会一直执行等待的 while 循环）即很多自旋
    - 通过 yield 主动放弃 CPU 资源来减少无用自旋
        ```c 
        void lock() {
            while (test_set(&flag, 1) == 1)
                yield();
        }
        void unlock() {
            flag = 0;
        }
        ```
        - 但是在多处理器上效率依旧不高

### 信号量
- 信号量（Semaphore）是一个整型变量
    - 表示可用资源的数量
- 只可以通过 wait 和 signal 来原子性修改信号量的值
    - wait 操作（P）会将信号量的值减一
    - signal 操作（V）会将信号量的值加一
- 二值信号量（Binary Semaphore）
    - 信号量的值只能为 0 或 1
    - 用于实现互斥锁
        ```c
        Semaphore mutex = 1;
        do {
            wait(mutex);
            // critical section
            signal(mutex);
            // remainder section
        } while (true);
        ```
- 计数信号量（Counting Semaphore）
    - 信号量的值可以为任意非负整数，来统计资源
- Waiting Queue
    - 每个信号量关联一个 waiting queue
    - wait 没有立即返回的话就加入 waiting queue
    - signal 的时候唤醒一个在 waiting 的进程
    - 不需要忙等待
    ```c
    void wait(Semaphore *S) {
        S->value--;
        if (S->value < 0) {
            add process to S->list;
            block();
        }
    }
    void signal(Semaphore *S) {
        S->value++;
        if (S->value <= 0) {
            remove a process P from S->list;
            wakeup(P);
        }
    }
    ```

### 死锁与饥饿
- 死锁（Deadlock）是指两个或多个进程互相等待对方释放资源，导致所有进程都无法继续执行的情况
- 饥饿（Starvation）是指一个进程由于长时间无法获得资源而无法继续执行的情况

#### 优先级反转
- 优先级反转（Priority Inversion）是指一个高优先级的进程由于等待一个低优先级的进程而导致自己的优先级降低，从而导致其他进程无法获得资源而无法继续执行的情况
- 例如：
    - 三个进程 A B C，优先级 A < B < C
    - 进程 A 持有锁，C 在等待这把锁
    - B 进程 ready 而且打断了 A
    - 效果上反转了 B 和 C 的优先级
- 解决方法：优先级继承（Priority Inheritance）
    - 临时的将持有锁的进程 A 的优先级赋值为正在等待的 C 的优先级