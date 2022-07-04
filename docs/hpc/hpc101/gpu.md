---
counter: True
comment: True
---

# GPU 编程

!!! abstract
    超算小学期第六次课课程内容，第三次实验内容

    参考：

    - 超算小学期第六次课 PPT
    - NVIDIA Deep Learning Institute：[加速计算基础 —— CUDA C/C++](https://www.nvidia.cn/training/instructor-led-workshops/fundamentals-of-accelerated-computing-with-cuda/)

## GPU

提供更高算力

- CPU：核数少、复杂；cache 很大；内存大但慢；适合串行或简单并行
- GPU：核数很多、简单；cache 很小；内存小但快；适合复杂并行

### 编程模型与硬件执行模型

- 硬件执行模型（Hardware Execution Model）<-> CUDA 编程模型
- GPU <-> Grid
- Streaming Multi-processor <-> Thread block
- CUDA core <-> Thread

GPU 编程模型是 SPMD（Single Program Multiple Data，单代码多数据），也就是 MultiThreaded

以以下代码为例

```cpp
for (int i = 0; i < N; ++i) {
    C[i] = A[i] + B[i];
}
```

- **SISD**（单指令单数据）：每层循环是 load load add store，循环 N 次
- **SIMD**（单指令多数据）：利用 SIMD 指令，减少循环次数，一次指令执行多次循环，load 多个数、add 多次、store 多次
- **SPMD**（单代码多数据）：执行时分为多个 thread，每个 thread 处理一次循环的数据

## CUDA

nvidia-smi 命令查看 GPU 信息

CUDA C/C++ 文件扩展名为 .cu，使用 nvcc 编译。一个 CUDA 代码的例子：

```cuda
void CPUFunction() {
    printf("This function is defined to run on the CPU.\n");
}

__global__ void GPUFunction() {
    printf("This function is defined to run on the GPU.\n");
}

int main() {
    CPUFunction();
    GPUFunction<<<1, 1>>>();
    cudaDeviceSynchronize();
}
```

其中一些 CUDA 特有内容的解释：

- **\_\_global\_\_ void GPUFunction()**
    - \_\_global\_\_ 关键字表明以下函数将在 GPU 上运行并可全局调用，而在此种情况下，则指由 CPU 或 GPU 调用
    - 通常，我们将在 CPU 上执行的代码称为主机代码，而将在 GPU 上运行的代码称为设备代码
    - 使用 \_\_global\_\_ 关键字定义的函数需要返回 void 类型
- **GPUFunction<<<1, 1>>>()**
    - 通常，当调用要在 GPU 上运行的函数时，我们将此种函数称为已启动的核函数
    - <<< ... >>> 语法提供执行配置，即线程块的数量和每个线程块内的线程数
- **cudaDeviceSynchronize()**
    - 核函数启动方式为异步：CPU 代码将继续执行而无需等待核函数完成启动。
    - 调用 CUDA 运行时提供的函数 cudaDeviceSynchronize 可以使主机（CPU）代码暂作等待，直至设备（GPU）代码执行完成，然后再恢复主机代码的执行

整个调用 GPU 的大致流程为：

![](/assets/images/hpc/hpc101/gpu/img1_light.png#only-light)
![](/assets/images/hpc/hpc101/gpu/img1_dark.png#only-dark)

- 先在 CPU 中进行正常 main 函数中的工作（即图中 initialize）
- 然后 CPU 调用 GPU 核函数 performWork()，同时 CPU 中继续进行它该做的其它工作（即图中 cpuWork）
- CPU 执行完 cpuWork() 后经过 cudaDeviceSynchronize() 与 GPU 同步，阻塞当前 CPU 任务，等待 GPU 的 performWork 执行完
- 同步后 CPU 继续执行剩下的 verifyWork()

### 编译
使用 nvcc 进行编译，例如：
```sh
$ nvcc -arch=sm_70 -o out code.cu -run
```
- 使用 sm_70 架构
- 编译 code.cu 文件
- 输出为 out 可执行文件
- -run 标志标识编译完立即执行

另外，可以使用 -std=c++11 来指定 C/C++ 语言版本

### 线程层次结构
正如前面 1.1 提到，CUDA 的线程层次结构从大到小为 Grid -> Thread Block -> Thread

结构示意图：

![](/assets/images/hpc/hpc101/gpu/img2_light.png#only-light)
![](/assets/images/hpc/hpc101/gpu/img2_dark.png#only-dark)

每个线程（Thread）中都运行一份核函数中内容，多个线程组成一个线程块（Thread Block），与核函数启动关联的所有块组成网格（Grid）

启动核函数时进行的配置就是 <<<*线程块数*, *每个块中线程数*>>>，其中每块中线程数一般最大为 1024

#### 线程层次结构变量
在核函数中可以直接访问 CUDA 提供的线程层次结构变量，常用的有：

- **gridDim.x**：Grid 中的 Block 数
- **blockIdx.x**：当前 Block 在 Grid 中的索引
- **blockDim.x**：每个 Block 中的 Thread 数
- **threadIdx.x**：当前 Thread 在所在的 Block 中的索引

#### 协调并行线程
例如并行加速 for 循环，为了使每个线程中核函数均处理不同的 i，访问内存 arr[i]，可以通过上面的变量进行计算：
```CUDA
i = threadIdx.x + blockIdx.x * blockDim.x
```
即每个线程处理的 i 为：

![](/assets/images/hpc/hpc101/gpu/img3_light.png#only-light)
![](/assets/images/hpc/hpc101/gpu/img3_dark.png#only-dark)

但这是理想情况，有两种特殊情况需要处理：

1. 总线程数多于要处理的数据数（或者说循环次数），则这样做会访问到非法内存
2. 总线程数少于要处理的数据数，则这样做会存在没有执行的循环

对于第一种，只需要在计算得到 i 之后与总数 n 比较，如果 i < n 则执行，否则在这个线程内什么都不做

对于第二种，则需要每个线程执行不止一个循环的工作，也就是使用**网格跨度循环**：

![](/assets/images/hpc/hpc101/gpu/img4_light.png#only-light)
![](/assets/images/hpc/hpc101/gpu/img4_dark.png#only-dark)

而每个线程进行循环的跨度恰好为 Grid 中的总线程数，因为 gridDim.x 表示 Grid 中 Block 数，blockDim.x 表示每个 Block 中 Thread 数，所以这个跨度恰好是 `#!cuda gridDim.x * blockDim.x`

因此 for 循环通过核函数在 GPU 中并行运行的常用写法是：
```cuda
__global__ void kernel(int *a, int N) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    int stride = gridDim.x * blockDim.x;
    for (int i = idx; i < N; i += stride) {
        // a[i] ...
    }
}
```

#### 二维和三维的网格和块
网格和线程块最多可以有三个维度，使用多维度定义网格和块不会对性能造成影响，但是在处理多维数据时会更方便

定义二维或三维的网格和块可以使用 CUDA 提供的 dim3 类型：
```cuda
dim3 threadsPerBlock(16, 16, 1);
dim3 numberOfBlocks(16, 16, 1);
kernel<<<numberOfBlocks, threadsPerBlock>>>(...);
```
在核函数中，`#!cuda gridDim.x` `#!cuda gridDim.y` `#!cuda blockDim.x` `#!cuda blockDim.y` 均为 16

二/三维循环的并行处理也类似上面一维情况：
```cuda
__global__ void kernel(int **a, int N1, int N2) {
    int idxx = threadIdx.x + blockIdx.x * blockDim.x;
    int stridex = gridDim.x * blockDim.x;
    int idxy = threadIdx.y + blockIdx.y * blockDim.y;
    int stridey = gridDim.y * blockDim.y;
    for (int i = idxx; i < N1; i += stridex) {
        for (int j = idxy; j < N2; j += stridey) {
            // a[i][j] ...
        }
    }
}
```

### 错误处理
许多 CUDA 函数会返回类型为 **cudaError_t** 的值，来用于后续检查调用函数时是否发生了错误，没有错误的值为 **cudaSuccess**，如果有错误，可以通过 **cudaGetErrorString** 来获取错误的具体内容。以 cudaMallocManaged 为例：
```cuda
cudaError_t err;
err = cudaMallocManaged(&a, N);
if (err != cudaSuccess) {
    printf("Error: %s\n", cudaGetErrorString(err));
}
```
但核函数没有返回值，因此检查启动核函数时是否发生错误（例如启动配置错误）需要使用 CUDA 提供的 **cudaGetLastError** 函数：
```cuda
kernel<<<1, -1>>>();
cudaError_t err;
err = cudaGetLastError;
if (err != cudaSuccess) {
    printf("Error: %s\n", cudaGetErrorString(err));
}
```
而为了捕获异步错误（如在核函数执行期间出现的错误），则需要检查 cudaDeviceSynchronize 的返回值，一个实用写法是：
```cuda
#include <assert.h>
inline cudaError_t checkCuda(cudaError_t result) {
    if (result != cudaSuccess) {
        fprintf(stderr, "CUDA Runtime Error: %s\n", cudaGetErrorString(result));
        assert(result == cudaSuccess);
    }
    return result;
}

int main() {
    ...
    kernel<<<..., ...>>>(...);
    checkCuda(cudaGetLastError());
    checkCuda(cudaDeviceSynchronize());
    ...
}
```

### 分配内存
C 分配内存使用的是 malloc 函数，但通过 malloc 得到的内存只能在 CPU 中访问

需要在 CPU 和 GPU 中同时访问某内存，需要通过 **cudaMallocManaged** 函数来分配，即：
```cuda
int *a;
size_t size = n * sizeof(int);
a = (int*)malloc(size) -> cudaMallocManaged(&a, size)
```
然后释放内存时使用 **cudaFree** 代替 free，即 cudaFree(a)

注意：利用 cudaMallocManaged 分配的内存可以在 CPU 和 GPU 中使用（后面会说），利用 cudaMalloc 分配的内存只可以在 GPU 中使用

### nsys 性能分析
nsys（Nsight System）是 CUDA 工具包附带的性能分析器，可以执行程序并生成包含 GPU 活动、CUDA API 调用、内存活动等信息的报告，也可以通过 GUI 查看时间轴

nsys 使用只需要指定 nvcc 编译好的可执行文件即可：
```sh
$ nsys profile --stats=true ./out
```
- 使用 nsys profile 进行分析
- --stats=true 表示向命令行中打印摘要信息
- 分析 out 程序

也可以使用 -o 指定报告输出文件，这个文件可以使用 Nsight System GUI 软件打开进行分析

nsys 默认不会覆盖原有报告，需要覆盖要使用 CLI flag --force-overwrite=true

### 流多处理器
流多处理器（SM，Streaming Multiprocessor）是运行 CUDA 的 GPU 上的处理单元

在核函数执行期间，线程块会提供给 SM 进行执行，因此为了支持 GPU 执行尽可能多的并行操作，提高 SM 的利用率进而提高性能，一般将线程块数（也就是网格维度）指定为 SM 数量的倍数

此外，SM 会在名为 Warp 的线程块内创建、管理、调度、执行包含 32 个线程的线程组，因此一般也将线程数量指定为 32 的倍数

### 查询 GPU 设备属性
CUDA 提供了获取当前处于活跃状态的 GPU 设备属性的 API：
```cuda
int deviceId;
cudaGetDevice(&deviceId);
cudaDeviceProp props;
cudaGetDeviceProperties(&props, deviceId);
```
其中 **cudaGetDevice** 获取设备 id，**cudaDeviceProp** 为属性的结构类型，**cudaGetDeviceProperties** 根据设备 id 获取具体属性

所有属性见：[NVIDIA CUDA 运行时文档](https://docs.nvidia.com/cuda/cuda-runtime-api/structcudaDeviceProp.html)

结合上面，一般设置块数和线程数使用：
```cuda
int deviceId;
int numberOfSMs;

cudaGetDevice(&deviceId);
cudaDeviceGetAttribute(&numberOfSMs, cudaDevAttrMultiProcessorCount, deviceId);

size_t threadsPerBlock = 256;
size_t numberOfBlocks = 32 * numberOfSMs;
```

### 统一内存
使用 cudaMallocManaged 分配的内存为统一内存（UM，Unified Memory）

统一内存在 CPU 和 GPU 分别访问时的行为如下：

![](/assets/images/hpc/hpc101/gpu/img5_light.png#only-light)
![](/assets/images/hpc/hpc101/gpu/img5_dark.png#only-dark)

- 刚开始时分配的内存不在 CPU 上也不在 GPU 上
- 哪一方先访问，会造成一个页错误（page fault），然后将需要的内存迁移到自己身上
- 另一方访问时也会造成页错误，然后再将需要的内存迁移到自己身上

数据从主机到设备的迁移记为 HtoD，从设备到主机的迁移记为 DtoH，通过 nsys 可以看到这些转移操作

在稀疏访问模式情况下，这样可以按需迁移内存，尤其是在多个 GPU 加速系统中，这样的按需迁移会有显著优势

有时可以将内存初始化放在 GPU 中进行，这样 UM 会先迁移到 GPU 中，然后驻留在 GPU 里进行后面的计算操作，这样可以减少在主机和设备之间的迁移次数，提高效率

#### 异步内存预取
但在某些情况下（比如需要连续大片内存），则预先将内存迁移出来可以规避页错误，并且减少按需内存迁移的成本

CUDA 可通过 **cudaMemPrefetchAsync** 函数来将 UM 预取到某一设备中，比如：
```cuda
int deviceId;
cudaGetDevice(&deviceId);

cudaMemPrefetchAsync(pointerToSomeUMData, size, deviceId);
...
cudaMemPrefetchAsync(pointerToSomeUMData, size, cudaCpuDeviceId);
```
cudaMemPrefetchAsync 需要提供 UM 的指针、大小、以及要预取到的设备。其中 deviceId 通过 cudaGetDevice 获取，cudaCpuDeviceId 是 CUDA 内置变量，表示 CPU

#### 手动内存分配
一些手动内存管理的 CUDA 函数：

- **cudaMalloc**：直接为 GPU 分配内存，防止出现 GPU 分页错误，但是 CPU 无法访问得到的内存指针
- **cudaMallocHost**：直接为 CPU 分配内存，称为固定内存（pinned memory）或页锁定内存（page-locked memory），允许将内存异步拷贝到 GPU 或从 GPU 异步拷贝回来。但固定内存过多会干扰 CPU 性能。释放时使用 **cudaFreeHost**
- **cudaMemcpy**：主机与设备之间拷贝内存
- **cudaMemcpyAsync**：主机与设备之间异步拷贝内存

示例：
```cuda
int *host_a, *device_a;        // Define host-specific and device-specific arrays.
cudaMalloc(&device_a, size);   // `device_a` is immediately available on the GPU.
cudaMallocHost(&host_a, size); // `host_a` is immediately available on CPU, and is page-locked, or pinned.

initializeOnHost(host_a, N);   // No CPU page faulting since memory is already allocated on the host.

// `cudaMemcpy` takes the destination, source, size, and a CUDA-provided variable for the direction of the copy.
cudaMemcpy(device_a, host_a, size, cudaMemcpyHostToDevice);

kernel<<<blocks, threads, 0, someStream>>>(device_a, N);

// `cudaMemcpy` can also copy data from device to host.
cudaMemcpy(host_a, device_a, size, cudaMemcpyDeviceToHost);

verifyOnHost(host_a, N);

cudaFree(device_a);
cudaFreeHost(host_a);          // Free pinned memory like this.
```

### 并发 CUDA 流
在 CUDA 中，核函数的执行以及一些内存传输均在 CUDA 流（CUDA Streams）中进行。默认情况下，直接启动核函数会在默认流中执行

在每一个流中，不同的核函数分别执行；但在不同流中，可以并发执行多个核函数

CUDA 流行为的几项规则：

- 给定流中的所有操作按序执行
- 不同非默认流中的操作无法保证彼此之间的执行顺序
- 默认流有阻断能力，即它会等待其它已在运行的所有流完成当前操作之后才会运行，并且在自身运行完毕之后其他流才可以继续下一操作的运行

也就是：

![](/assets/images/hpc/hpc101/gpu/img6_light.png#only-light)
![](/assets/images/hpc/hpc101/gpu/img6_dark.png#only-dark)

核函数在各流中执行的情况也可以通过 nsys 可视化分析看出来

#### 创建、使用、销毁非默认流
CUDA 中流的类型为 **cudaStream_t**，并且利用 **cudaStreamCreate** 创建非默认流，然后作为第四个执行配置参数传给核函数。在使用后利用 **cudaStreamDestroy** 销毁流。一个例子：
```cuda
cudaStream_t stream;
cudaStreamCreate(&stream);
kernel<<<number_of_blocks, threads_per_block, 0, stream>>>();
cudaStreamDestroy(stream);
```
几个需要注意的地方：

- cudaStreamCreate 接收 stream 的指针
- cudaStreamDestroy 接收 stream 值（不是指针）
- 执行配置的第三个参数与共享内存（Shared Memory）有关，默认为 0

#### 使用流实现数据传输和代码的重叠执行

![](/assets/images/hpc/hpc101/gpu/img7_light.png#only-light)
![](/assets/images/hpc/hpc101/gpu/img7_dark.png#only-dark)

在以下示例中，我们并非在等待整个内存拷贝完成之后再开始运行核函数，而是拷贝并处理所需的数据段，并让每个拷贝/处理中的数据段均在各自的非默认流中运行。通过使用此技术，您可以开始处理部分数据，同时为后续段并发执行内存传输。使用此技术计算操作次数的数据段特定值和数组内的偏移位置时必须格外小心，如下所示：
```cuda
int N = 2<<24;
int size = N * sizeof(int);

int *host_array;
int *device_array;

cudaMallocHost(&host_array, size);               // Pinned host memory allocation.
cudaMalloc(&device_array, size);                 // Allocation directly on the active GPU device.

initializeData(host_array, N);                   // Assume this application needs to initialize on the host.

const int numberOfSegments = 4;                  // This example demonstrates slicing the work into 4 segments.
int segmentN = N / numberOfSegments;             // A value for a segment's worth of `N` is needed.
size_t segmentSize = size / numberOfSegments;    // A value for a segment's worth of `size` is needed.

// For each of the 4 segments...
for (int i = 0; i < numberOfSegments; ++i) {
    // Calculate the index where this particular segment should operate within the larger arrays.
    segmentOffset = i * segmentN;

    // Create a stream for this segment's worth of copy and work.
    cudaStream_t stream;
    cudaStreamCreate(&stream);
  
    // Asynchronously copy segment's worth of pinned host memory to device over non-default stream.
    cudaMemcpyAsync(&device_array[segmentOffset],  // Take care to access correct location in array.
                    &host_array[segmentOffset],    // Take care to access correct location in array.
                    segmentSize,                   // Only copy a segment's worth of memory.
                    cudaMemcpyHostToDevice,
                    stream);                       // Provide optional argument for non-default stream.
                  
    // Execute segment's worth of work over same non-default stream as memory copy.
    kernel<<<number_of_blocks, threads_per_block, 0, stream>>>(&device_array[segmentOffset], segmentN);
  
    // `cudaStreamDestroy` will return immediately (is non-blocking), but will not actually destroy stream until
    // all stream operations are complete.
    cudaStreamDestroy(stream);
}
```