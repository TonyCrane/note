---
comment: True
counter: True
---

# 排序与哈希

!!! abstract
    「数据结构基础」课程 排序、哈希 部分内容复习与总结

## 排序
### 插入排序
```c 
void insertionSort(int arr[], int n) {
    for (int P = 1; P < n; ++P) {
        int tmp = arr[P];
        int i;
        for (i = P; i > 0 && arr[i - 1] > tmp; --i)
            arr[i] = arr[i - 1];
        arr[i] = tmp;
    }
}
```

- 进行 $n-1$ 趟（pass）排序
- 第 $P$ 趟时保证从位置 0 到 $P-1$ 上的元素以及排好序，然后将第 $P$ 个元素插入到前面的有序序列的正确位置处
- 最坏（A 是逆序的）复杂度 $O(N^2)$
- 最好（A 是有序的）复杂度 $O(N)$

### 希尔排序
- 希尔排序（shell sort）使用一个增量序列 $h_1<h_2<\cdots<h_t$，其中 $h_i$ 为整数，且 $h_i=1$
- 定义 $h_k$-sort 为将原数组隔 $h_k-1$ 个元素分为一组，每组内进行排序
- $k = t, t-1, \cdots, 1$ 依次进行 $h_k$-sort，最终得到一个有序序列
    - $h_k$-sorted 的序列在 $h_{k-1}$-sorted 后仍保持 $h_k$-sorted 的性质
- 希尔排序的复杂度和增量序列的选取有关
- 希尔增量序列：$h_t=\lfloor N/2\rfloor, h_k = \lfloor h_{k+1}/2\rfloor$
    - 最坏复杂度 $O(N^2)$（即只在 1-sort 时进行了排序）

    ??? success "代码"
        ```c 
        void shellSort(int arr[], int n) {
            int i, j, tmp;
            for (int inc = N/2; inc > 0; inc /= 2) {
                for (i = inc; i < N; ++i) {
                    tmp = arr[i];
                    for (j = i; j >= inc; j -= inc) {
                        if (tmp < arr[j - inc])
                            arr[j] = arr[j - inc];
                        else
                            break;
                    }
                    a[j] = tmp;
                }
            }
        }
        ```

- Hibbard 增量序列：$h_k = 2^k-1$
    - 最坏复杂度 $O(N^{3/2})$
    - 平均复杂度 $O(N^{5/4})$

### 堆排序
- 使用堆结构来进行排序
- 算法一：将数组中的元素依次插入到堆中（可以是 $O(N)$ 线性建堆），然后依次从堆中取出最小元素
    - 复杂度 $O(N\log N)$
    - 但是空间消耗翻倍了
- 算法二：
    - 以线性时间建最大堆（PercolateDown）
    - 将堆顶元素与最后一个元素交换（相当于删除最大元素），然后进行 PercolateDown
    - 依此循环，N-1 次删除后得到一个从小到大的序列
    ```c 
    void heapSort(int arr[], int n) {
        for (int i = n / 2; i >= 0; --i) 
            percolateDown(arr, i, n);
        for (int i = n - 1; i > 0; --i) {
            swap(&arr[0], &arr[i]);
            percolateDown(arr, 0, i);
        }
    }
    ```
    - 平均比较次数为 $2N\log N - O(N\log\log N)$

### 归并排序
- 关键的操作是合并两个有序列表变成一个有序列表，可以在 $O(n)$ 时间内完成
- 归并操作则可以递归进行，分而治之，依次合并
- 复杂度：

$$
\begin{align*}
T(1) &= 1\\
T(N) &= 2T(\frac{N}{2}) + O(N)\\
&= 2^kT(\frac{N}{2^k})+k\cdot O(N)\\
&= N\cdot T(1) + \log N \cdot O(N)\\
&= O(N + N\log N) = O(N\log N)
\end{align*}
$$

??? success "代码"
    ```c 
    void mergeSort(int arr[], int n) {
        int *tmp = malloc(sizeof(int) * n);
        if (tmp != NULL) {
            mergeSortHelper(arr, tmp, 0, n - 1);
            free(tmp);
        } else {
            printf("No space for tmp array!\n");
        }
    }

    void mergeSortHelper(int arr[], int tmp[], int left, int right) {
        if (left < right) {
            int center = (left + right) / 2;
            mergeSortHelper(arr, tmp, left, center);
            mergeSortHelper(arr, tmp, center + 1, right);
            merge(arr, tmp, left, center + 1, right);
        }
    }

    void merge(int arr[], int tmp[], int leftPos, int rightPos, int rightEnd) {
        int leftEnd = rightPos - 1;
        int tmpPos = leftPos
        int numElements = rightEnd - leftPos + 1;
        while (leftPos <= leftEnd && rightPos <= rightEnd)
            if (arr[leftPos] <= arr[rightPos])
                tmp[tmpPos++] = arr[leftPos++];
            else
                tmp[tmpPos++] = arr[rightPos++];
        while (leftPos <= leftEnd)
            tmp[tmpPos++] = arr[leftPos++];
        while (rightPos <= rightEnd)
            tmp[tmpPos++] = arr[rightPos++];
        for (int i = 0; i < numElements; ++i, rightEnd--)
            arr[rightEnd] = tmp[rightEnd];
    }
    ```

### 快速排序
- 已知的实际运行最快的排序算法
- 选择一个基准元素（枢轴 pivot），将数组分成两个子数组，左边的元素都小于等于基准元素，右边的元素都大于等于基准元素，然后对两个子数组进行快排、合并
- 选取 pivot
    - 错误方法：pivot = arr[0]（对于排好序的数组仍会消耗 $O(N^2)$ 的时间）
    - 安全方法：pivot = random element in arr
        - 但随机数生成也有开销
    - 三数中值分割法：pivot = (left + center + right) / 3
- ~~划分策略~~（看不懂 PPT 在干什么）
- 小数组
    - 对于小的 $N$（$N\leq 20$），快速排序慢于插入排序
    - 可以在递归到 $N$ 较小的情况下改为插入排序
- 最坏复杂度 $O(N^2)$
- 最优复杂度 $O(N\log N)$
- 平均复杂度 $O(N\log N)$

### 桶排序
- 如果输入数据都小于 $M$，则可以用一个大小为 $M$ 的数组来记录某个值出现了多少次，这个数组称为桶（bucket）
- 桶初始化为 0，遍历输入数据，将每个数据对应的桶加 1
- 最后遍历桶中的所有元素，对于 bucket[x] = y，将 x 输出 y 次
- 时间复杂度 $O(N+M)$

### 基数排序
- 从低位（LSD，Least Significant Digit）到高位（MSB），对每一位进行进行排序
- 例如对 64, 8, 216, 512, 27, 729, 0, 1, 343, 125 进行排序
    - 第一轮，按个位数排序
        - 0, 1, 512, 343, 64, 125, 216, 27, 8, 729
    - 第二轮，按十位数排序
        - (0, 1, 8), (512, 216), (125, 27, 729), 343, 64
    - 第三轮，按百位数排序
        - (0, 1, 8, 27, 64), 125, 216, 343, 512, 729
    - 完成排序
- 时间复杂度 $O(P(N+B))$，其中 $P$ 为轮数，$N$ 为元素个数，$B$ 为桶个数

### 稳定性
- 对于一个序列，如果存在两个相等的元素
    - 排序后它们的相对位置不变，则称这个排序算法是稳定的
    - 排序后它们的相对位置发生了变化，则称这个排序算法是不稳定的
- 稳定排序：冒泡、归并、插入、基数
- 不稳定排序：快排、希尔、堆排、选择

## 哈希

!!! warning
    这部分的 PPT 真的是乱的离谱，看的半懂不懂

### 哈希表
- 哈希表（hash table）也称为散列表，是一种数据结构，它通过把关键字值映射到表中一个位置来访问记录，以加快查找的速度
    - 支持查找关键字是否在表中、查询关键字、插入关键字、删除关键字等操作
    - 关键字也称为标识符（identifier）
- 通常用一个数组来实现，也可以有多个槽（slot），即多个关键字对应同一个位置时，将不同关键字存在同一个位置的不同槽中
- 对于标识符 $x$，定义一个哈希函数 $f(x)$ 表示 $x$ 在哈希表 ht[] 中的位置（索引）
- 设哈希表 ht 的大小为 $b$（即 $f(x)$ 值域为 $[0, b-1]$），最多有 $s$ 个槽，则定义以下值：
    - $T$ 表示 $x$ 可能的不同值个数
    - $n$ 表示 ht 中所有不同标识符的个数
    - 标识符密度定义为 $n/T$
    - 装载密度定义为 $\lambda = n/(sb)$
- 当存在 $i_1 \neq i_2$ 但 $f(i_1) = f(i_2)$ 的情况，则称为发生了碰撞（collision）
- 当将一个新的标识符映射到一个满的桶时，则称为发生了溢出（overflow）
    - 当 s = 1 时，碰撞和溢出将同时发生

### 哈希函数
- 哈希函数应该易于计算，并且减少碰撞的可能性
- 哈希函数应该是 unbiased 的，即 $P(f(x) = i) = 1/b$，这种函数称为均匀哈希函数（uniform hash function）
- 对于整数的哈希，例如 $f(x) = x \bmod \mathrm{tableSize}$，其中 tableSize 最好选择一个质数，这样对于随机输入，关键字的分布更均匀

### 分离链接
- 解决冲突的一种方法是分离链接（separate chaining）
- 将哈希映射到同一个值的所有元素保存在一个列表（链表）中

??? success "代码"
    ```c
    struct ListNode;
    typedef struct ListNode *Position;
    struct HashTbl;
    typedef struct HashTbl *HashTable;
    struct ListNode {
        ElementType Element;
        Position Next;
    };
    typedef Position List;
    struct HashTbl {
        int TableSize;
        List *TheLists;
    };

    HashTable initializeTable(int tableSize) {
        HashTable H;
        if (tableSize < minTableSize) {
            printf("Table size too small");
            return NULL;
        }
        H = malloc(sizeof(struct HashTbl));
        if (H == NULL) Error("Out of space!!!");
        H->TableSize = nextPrime(tableSize);
        H->TheLists = malloc(sizeof(List) * H->TableSize);
        if (H->TheLists == NULL) Error("Out of space!!!");
        for (int i = 0; i < H->tableSize; ++i) {
            H->TheLists[i] = malloc(sizeof(struct ListNode));
            if (H->TheLists[i] == NULL) Error("Out of space!!!");
            else H->TheLists[i]->Next = NULL;
        }
        return H;
    }

    Position find(ElementType key, HashTable H) {
        Position P; List L;
        L = H->TheLists[hash(key, H->TableSize)];
        P = L->Next;
        while (P != NULL && P->Element != key) P = P->Next;
        return P;
    }

    void insert(ElementType key, HashTable H) {
        Position pos, newCell; List L;
        pos = find(key, H);
        if (pos == NULL) {
            newCell = malloc(sizeof(struct ListNode));
            if (newCell == NULL) Error("Out of space!!!");
            else {
                L = H->TheLists[hash(key, H->TableSize)];
                newCell->Next = L->Next;
                newCell->Element = key;
                L->Next = newCell;
            }
        }
    }
    ```

### 开放地址
- 开放地址（open addressing）是另一种解决冲突的方法
- 当有冲突发生时，尝试选择其它单元，直到找到空的为止
- 即有多个哈希函数 $h_0(x), h_1(x), \cdots$，其中 $h_i(x) = (\mathrm{hash}(x)+f(i))\bmod \mathrm{tableSize}$
    - 其中 $f(i)$ 为增量函数，有多种选取的方式
- 一般来说 $\lambda < 0.5$

```c 
void insert(int key) {
    index = hash(key);
    int i = 0;
    while (collision at index) {
        index = (hash(key) + f(i)) % tableSize;
        if (table is full) break;
        else i++;
    }
    if (table is full) Error("No space left");
    else table[index] = key;
}
```

#### 线性探测
- 即增量函数的选择为 $f(i) = i$
- 即冲突了就往后一个一个找，直到找到空的为止
- 会导致聚集（clustering），即一旦发生了冲突，那么后面的元素都会聚集在一起，搜索次数会变得非常大
    - 使用线性探测的探测次数对于插入和不成功查找来说约为 $\dfrac{1}{2}\left(1+\dfrac{1}{(1-\lambda)^2}\right)$
    - 对于成功的查找来说则需要 $\dfrac{1}{2}\left(1+\dfrac{1}{1-\lambda}\right)$ 次

#### 二次探测
- 即 $f(i) = i^2$
- 如果使用二次探测，且表大小为质数时，那么当表至少有一半是空的时，总能插入一个新的元素
- 查找
    - $f(i) = f(i-1) + i^2 - (i-1)^2 = f(i-1) + 2i - 1$
    ```c 
    Position find(ElementType key, HashTable H) {
        Position currentPos = hash(key, H->TableSize);
        int collisionNum = 0;
        while (H->TheCells[currentPos].Info != Empty && 
            H->TheCells[currentPos].Element != key) {
            currentPos += 2 * ++collisionNum - 1;
            if (currentPos >= H->TableSize) currentPos -= H->TableSize;
        }
        return currentPos;
    }
    ```
- 插入
    ```c 
    void insert(ElementType key, HashTable H) {
        Position pos = find(key, H);
        if (H->TheCells[pos].Info != Legitimate) {
            H->TheCells[pos].Info = Legitimate;
            H->TheCells[pos].Element = key;
        }
    }
    ```

#### 双重哈希
- 即 $f(i) = i * \mathrm{hash}_2(x)$
- 一般选择 $\mathrm{hash}_2(x) = R - (x\bmod R)$，其中 $R$ 为小于表大小的质数
- 如果双重哈希正确实现了，那么预期的探测次数和随机的碰撞解决策略几乎相同（？听不懂）
- 二次探测不需要使用第二个哈希函数，所以相比之下二次探测更简单快速

### 再哈希
- 使用二次探测，如果表的元素过多，那么操作时间会过长，而且可能插入失败
- 解决方法是再哈希（rehashing）
    - 建立一个两倍大的哈希表
    - 扫描原始哈希表
    - 利用新的哈希函数将元素映射到新的哈希值，并插入
- 如果有原来的哈希表有 $N$ 个元素，则再哈希的时间复杂度为 $O(N)$
- 什么时候进行再哈希
    - 表填满一半了
    - 插入失败
    - 当哈希表达到了某一个特定的装载密度时