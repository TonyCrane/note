---
counter: True
comment: True
---

# spike 工具链的调试与时钟中断学习

!!! abstract
    想探索一下在 OS 课上写一个指导来让同学们可以像系统一样选择 [spike](https://github.com/riscv-software-src/riscv-isa-sim/) 来进行 RISC-V kernel 调试。当时系统三助教的时候用过，但是 spike 是学长改过的 [riscv-isa-cosim](https://github.com/sycuricon/riscv-isa-cosim)（加了 CJ 也就是 difftest 的部分），这个目前已经有段时间没更新了，所以在尝试使用最新版本 OpenSBI（启用 PIE 编译）的时候无法加载 ELF（还不支持 PIE），于是就更换成了最新的 spike，然后就有了以下的调试过程。

    同步发布在 blog：<https://blog.tonycrane.cc/p/9188d8c1.html>

    本文中出现源码的版本：

    - opensbi: c4940a9517486413cd676fc8032bb55f9d4e2778
    - riscv-isa-sim: 0cc5ecce053c6dfa44e4a865d2838fc8d7d771dc

## 关于工具链

Spike 这套东西的逻辑就是，spike 自身是一个专注于 RISC-V 规范的模拟器，而且也模拟了硬件机制，在调试时需要通过 JTAG 来调试，并且开了一个 remote bitbang 的端口用来收发指令。然后使用 [OpenOCD](https://github.com/openocd-org/openocd/) 来连接这个 rbb 端口进行指令的解析，再开一个端口来供 GDB 读取这些信息进行调试。

Spike 是从 repo 中安装的最新版：

```bash
git clone https://github.com/riscv-software-src/riscv-isa-sim
cd riscv-isa-sim
sudo apt install device-tree-compiler libboost-regex-dev libboost-system-dev
mkdir build
cd build
../configure
make -j$(nproc)
sudo make install
```

OpenOCD 是直接 apt 安装的，OpenSBI 也是 repo 中的最新版：

```bash
git clone https://github.com/riscv-software-src/opensbi
cd opensbi
mkdir build
make O=build CROSS_COMPILE=riscv64-linux-gnu- PLATFORM=generic
# output: build/platform/generic/firmware/fw_jump.elf
```

然后一些命令：

```makefile
spike_run: all
	@echo Launch the spike ......
	@spike --kernel=arch/riscv/boot/Image $(SPIKE_CONFIG)/fw_jump.elf

spike_debug: all
	@echo Launch the spike for debug ......
	@spike -H --rbb-port=9824 --kernel=arch/riscv/boot/Image $(SPIKE_CONFIG)/fw_jump.elf

spike_bridge:
	@echo Launch the OpenOCD ......
	@openocd -f $(SPIKE_CONFIG)/spike.cfg
```

其中 OpenOCD 的配置文件 `spike.cfg` 如下（最开始的版本）：

```bash
adapter driver remote_bitbang
remote_bitbang_host localhost
remote_bitbang_port 9824

set _CHIPNAME riscv
jtag newtap $_CHIPNAME cpu -irlen 5 

set _TARGETNAME $_CHIPNAME.cpu
target create $_TARGETNAME riscv -chain-position $_TARGETNAME

bindto 0.0.0.0
gdb_report_data_abort enable

init
halt
```

`make spike_run` 就是直接运行 kernel，`make spike_debug` 开启调试模式，再另开一个终端跑 `make spike_bridge` 启动 OpenOCD 然后就可以用 GDB 连接了。

## GDB 调试时不断遇到 SIGINT

刚开始的时候 spike_run 没问题，但是一旦调试起来，连接上后再 b _start，随后 c 的话就会在中间多次遇到 SIGINT 导致调试暂停，即使 `handle SIGINT nostop` 的话也会看到跑到 _start 之前一直在忽略 SIGINT 而且效率极低。

这个问题调的很痛苦，因为在同一 OpenOCD 和配置下，用同样 OpenSBI，使用最新 spike 和老的 cosim 的结果不一样（cosim 不会 SIGINT），所以问题就被锁定在 spike 身上了。

起初我认为是 spike 添加了 debug triggers 的问题，因为我是头一次在 OpenSBI 的输出中看到 sdtrig 指令集扩展，然后看到了 4 triggers，但是虽然有 `--trigger` 参数来指定数量，也不能使它小于 1。同时即使设定了 `--isa=RV64gc` 不带任何扩展，也会自动加上 sdtrig。当时几乎就认定是 trigger 的问题了，但是后来在 riscv/processor.cc 中发现了函数 `processor_t::take_trigger_action`，在这个开头把输出的 trigger 信息硬性要求输出到 stdout 中，发现并没有输出：

```cpp title="(spike) riscv/processor.cc" linenums="543"
void processor_t::take_trigger_action(triggers::action_t action, reg_t breakpoint_tval, reg_t epc, bool virt)
{
  if (debug) {
    std::stringstream s; // first put everything in a string, later send it to output
    s << "core " << std::dec << std::setfill(' ') << std::setw(3) << id
      << ": trigger action " << (int)action << std::endl;
    debug_output_log(&s);
  }
```

而且同样我在 `processor_t::take_trap` 开头把输出也强制打开了，也只能发现在 0x80000000 之后（屏蔽了这前面的部分，因为 0x1000 前会有 debug rom 一直在运行一直在 trap）只出现过一个 store access fault 的 trap。所以那就能排除掉 trigger 的问题了。

接着我从源码安装了 OpenOCD（v0.12+）：

```bash
git clone https://github.com/openocd-org/openocd/
cd openocd
sudo apt install libtool
./bootstrap
./configure --enable-remote-bitbang
make
# output: src/openocd
```

与本地的 v0.11 的相比，它运行时多了一些 error，而且恰巧在每次 SIGINT 的同时都能看到新增了一条 error：

```text
Warn : Failed to read memory via program buffer.
Error: Failed write (NOP) at 0x7; status=2
Error: Failed write (NOP) at 0x6; status=2
Warn : Failed to read memory via abstract access.
Error: Target riscv.cpu: Failed to read memory (addr=0x0)
Error:   progbuf=failed, sysbus=skipped (unsupported size), abstract=failed
```

我又认为这是 OpenOCD+GDB 在调试时访问 0x0 处的非法内存导致的，经学长解答，0x0 开始的这部分是一个 debug module，在调试的时候是会用到的。在 riscv/sim.cc 的 `sim_t::sim_t` 函数中也看到了开头就有一句 `bus.add_device(DEBUG_START, &debug_module);`，然后我又去翻了翻 debug module，它在一些指定的位置才放了内存，比如 0x800 开始放了 debug rom，0x374 这里放了 progbuf，而其他没放的地方访问的时候都会像这样出错。这部分逻辑在 riscv/debug_module.cc 的 `debug_module_t::load` 中：

```cpp title="(spike) riscv/debug_module.cc" linenums="125"
bool debug_module_t::load(reg_t addr, size_t len, uint8_t* bytes)
{
  addr = DEBUG_START + addr;

  if (addr >= DEBUG_ROM_ENTRY &&
      (addr + len) <= (DEBUG_ROM_ENTRY + debug_rom_raw_len)) {
    memcpy(bytes, debug_rom_raw + addr - DEBUG_ROM_ENTRY, len);
    return true;
  }
  
  ...

  D(fprintf(stderr, "ERROR: invalid load from debug module: %zd bytes at 0x%016"
          PRIx64 "\n", len, addr));

  return false;
}
```

学长说 cosim 里面屏蔽了 0x0 这个地址，然后在这个地址的位置放了一个随机数设备来防止读取出问题，但我还是想找到问题所在，所以继续调了。

将末尾的 D() 去掉，然后 return true 就能让所有 0x0 - 0x1000 的访存合法，再跑一次发现 OpenOCD 那里确实没有报错了，然后每次都会从 0x0 开始请求一串内存，这里都会报 ERROR。但即使 OpenOCD 没了报错，GDB 还是会像原先一样隔一阵遇到一个 SIGINT，所以那这个 SIGINT 也不是由于 OpenOCD 读 debug 信息错误导致的。

接下来就翻了翻 OpenOCD 的文档，发现了在 GDB 相关的 20.2 节给出了一个简单的 GDB 调试案例：

```text
$ arm-none-eabi-gdb example.elf
(gdb) target extended-remote localhost:3333
Remote debugging using localhost:3333
...
(gdb) monitor reset halt
...
(gdb) load
Loading section .vectors, size 0x100 lma 0x20000000
Loading section .text, size 0x5a0 lma 0x20000100
Loading section .data, size 0x18 lma 0x200006a0
Start address 0x2000061c, load size 1720
Transfer rate: 22 KB/sec, 573 bytes/write.
(gdb) continue
Continuing.
...
```

这里多了一句 `monitor reset halt` 不知道是干什么，然后随手一试，加上这一句之后 SIGINT 就消失了，可以正常调试了。或者在 spike.cfg 配置的最后把 `halt` 改成 `reset halt` 也可以，因为 GDB 的 `monitor` 就相当于发指令给 OpenOCD。又搜了一些也没找到这样做的理由，听到的说法都是刷新程序，让它好接收后面的断点和调试。所以调了好久最后原因是 OpenOCD 的配置问题，但为什么 cosim 的老 spike 没遇到问题还是没解决，但已经无所谓了感觉。

## Semihosting 相关

接下来没有 SIGINT 就可以一直跑起来的，但是并没有断在 _start 的断点的位置，而是在 OpenSBI 中的 ebreak，这个 ebreak 是在 `_semihost_test_vector_next` 标号里的，这个是由 OpenSBI 的 lib/utils/serial/semihosting.c 的 semihosting_enabled 函数引入的。学长说是因为 spike 并没有支持 semihosting 机制，所以在之前使用的 OpenSBI 中手动在 semihosting_enabled 和 semihosting_trap 函数的开头直接 return 了 0 来 patch 掉。

搜了一下 semihosting 相关，这是一个由 arm 引入的调试方法。因为硬件上通过串口输出还要经过设备时序等一系列，会加重调试负担，所以 semihosting 机制通过将输出等一系列功能交给调试主机来做，这样就不需要硬件串口支持了。只需要在比如 print 输出的时候调用一下 SVC HLT BKPT 等可以让调试器接手的指令，然后调试器会安装协议读取要进行的操作等，由调试器来进行输出。

在 RISC-V 上，这样陷入调试器的指令是 ebreak，但是也只有 ebreak，无法区分普通 ebreak 和 semihosting 用的 ebreak。所以 RISC-V 规定，semihosting 的 ebreak 前后会跟两条特殊的 nop 指令，形成：

```asm
slli x0, x0, 0x1f
ebreak
srai x0, x0, 7
```

调试器在遇到 ebreak 之后可以检查前后两条指令，如果是这样的形式，那么就是 semihosting 的 ebreak，否则就是普通的 ebreak。这个是在 RISC-V 的 [riscv-non-isa/riscv-semihosting](https://github.com/riscv-non-isa/riscv-semihosting) 中规定的。

看了 spike 的源码，关于 ebreak 指令的处理确实没有检查前后两条指令的操作。但转念一想，spike 作为一个指令模拟器，它就是一个待调试的硬件设备，而真正处理 semihosting 的应该是调试器，而在这套工具链里调试器是 OpenOCD，所以实际的工作应该在 OpenOCD 层面，在收到 ebreak 之后额外检查两条指令。

经过搜索，OpenOCD 还真有这么一条指令 `arm semihosting enable`，也就是 GDB 里的 `monitor arm semihosting enable`。跑了这条指令之后 GDB 就不会再卡在 semihosting 的 ebreak 了，因为这部分已经被 OpenOCD 解析成了 semihosting 请求来特殊处理了，而且 OpenSBI 输出的 platform console device 也从 uart8250 变成了 semihosting。也因此，输出等操作就由 OpenOCD 来完成了，而非 spike 的串口。所以这时候的内核输出在运行着 `make spike_bridge` 的终端里，而且这套效率并比不上串口，所以效率很低，以至于效果上是逐个字进行输出。

所以为了调试效率，还是不启用 semihosting 为好，但也不用直接 patch 掉相关逻辑，OpenSBI 提供了 kconfig 来进行配置，可以直接：

```shell
make PLATFORM=generic menuconfig
```

然后将 Utils and Drivers Support > Serial Device Support > Semihosting support 关掉再 make 就好了。

## 时钟中断相关

最后一个问题是 spike 运行的 kernel 的时钟中断周期和 busy loop 长度都要少一个 0 才能达到和 qemu 一样的效果，也就是实际上的时钟频率是 1_000_000 Hz，不过 spike 运行的 OpenSBI 输出的 platform timer device 还是都是一样的 aclint-mtimer @ 10000000Hz。

找了 OpenSBI 的源码，对于 generic platform，timer 的频率是从设备树中读取的。generic 使用了 fdt_timer_mtimer，其中的 cold init 调用了 OpenSBI 的 lib/utils/timer/fdt_timer_mtimer.c 的 `timer_mtimer_cold_init` 函数：

```c title="(opensbi) lib/utils/timer/fdt_timer_mtimer.c" linenums="33"
static int timer_mtimer_cold_init(const void *fdt, int nodeoff,
				  const struct fdt_match *match)
{
    ...

	rc = fdt_parse_timebase_frequency(fdt, &mt->mtime_freq);
	if (rc) {
		sbi_free(mtn);
		return rc;
	}
```

这里 `fdt_parse_timebase_frequency` 就是在读取设备树中的 `timebase-frequency` 属性，而这个属性在 spike 导出时就是 10_000_000：

```cpp title="(spike) riscv/sim.cc" linenums="145"
    dts = make_dts(INSNS_PER_RTC_TICK, CPU_HZ, cfg, mems, device_nodes);
```

```cpp title="(spike) riscv/dts.cc" linenums="59"
         "    timebase-frequency = <" << (cpu_hz/insns_per_rtc_tick) << ">;\n";
```

这里 CPU_HZ 是 1_000_000_000，INSNS_PER_RTC_TICK 是 100，所以 freq 是 10_000_000 没错。

但为什么 spike 跑起来实际比这个要慢得多呢，按理说 10_000_000Hz 的时钟频率，设定 10_000_000 的时钟中断间隔那出现的就是 1s 一个，为什么会 10s 一个。原因在于 spike 对于 mtime 的处理：

```cpp title="(spike) riscv/clint.cc" linenums="100"
void clint_t::tick(reg_t rtc_ticks)
{
  if (real_time) {
   struct timeval now;
   uint64_t diff_usecs;

   gettimeofday(&now, NULL);
   diff_usecs = ((now.tv_sec - real_time_ref_secs) * 1000000) + (now.tv_usec - real_time_ref_usecs);
   mtime = diff_usecs * freq_hz / 1000000;
  } else {
    mtime += rtc_ticks;
  }

  for (const auto& [hart_id, hart] : sim->get_harts()) {
    hart->state.time->sync(mtime);
    hart->state.mip->backdoor_write_with_mask(MIP_MTIP, mtime >= mtimecmp[hart_id] ? MIP_MTIP : 0);
  }
}
```

clint 是 Core Local Interruptor，局部中断器，负责产生软件中断和时钟中断。这里也看得出，在 `mtime >= mtimecmp[hard_id]` 的时候设置 mip 的 mtip 位，即告诉 core 又一个时钟中断在等待处理。

而 mtime 更新的逻辑在前面，如果有 real_time 的情况下，mtime 按照实际时间更新，假设我们经过了 1s 的时间，那 diff_usecs 就是 1_000_000，所以 mtime = freq_hz，也就是 10_000_000，这样 1s 之后 mtime 就多了 10_000_000，如果 mtimecmp 设置的间隔也是这个，那就是 1s 一个中断。实际跑起来，如果加上 `--real-time-clint` 的话，时钟中断确实就 1s 出现一个了（间隔 10_000_000）。

那如果不加 real_time 呢，也就是说为什么之前会出现 10s 一个中断的情况。我们再次假设 mtimecmp 的间隔是 10_000_000，看一下多久会触发，也就是 mtime 什么时候能多加 10_000_000 个 rtc_ticks。因为 INSN_PER_RTC_TICK 是 100，所以跑 100 条指令多一个 rtc_tick，那触发一次时钟中断就要跑 1_000_000_000 条指令，也就是说只和跑了多少条指令有关，和实际时间无关，所以体感 10s 一个中断实际上是纯粹的 spike 跑的慢。

所以为了 qemu 和 spike 一样的表现，只需要在 spike 运行的时候加上 `--real-time-clint` 就好了，以及如果有 busy loop 输出的话还需要按 10 倍的规模调整一下循环次数。

### 关于 memory-mapping 与 stimecmp

调试的时候有的时候想要找 mtime 和 mtimecmp 的值到底是多少，但是 GDB 并不能读取这两个寄存器，因为他们两个都是 memory mapping 的，也就是说他们的实际位置在内存上而非寄存器中。所以我们可以通过读取内存来获取这两个值：

```shell
p/x {unsigned long long}0x2004000 # mtimecmp
p/x {unsigned long long}0x200bff8 # mtime
```

Spike 和 qemu 都是同样的地址（spike 相关代码同样可以在 riscv/clint.cc 中找到，也就是 load 和 store 两个函数）。

但是有些情况下即使设置了 mtimecmp 也不会发现 0x2004000 地址上有变化（比如较新的 qemu 跑最新的 OpenSBI）。我们可以通过 sbi 来调查这个问题，时钟中断的设置是通过调用 sbi_set_timer 完成的，通过翻 OpenSBI 源码可以找到这个 set_timer 的实际处理函数在 lib/sbi/sbi_timer.c 里：

```c title="(opensbi) lib/sbi/sbi_timer.c" linenums="132"
void sbi_timer_event_start(u64 next_event)
{
	sbi_pmu_ctr_incr_fw(SBI_PMU_FW_SET_TIMER);

	/**
	 * Update the stimecmp directly if available. This allows
	 * the older software to leverage sstc extension on newer hardware.
	 */
	if (sbi_hart_has_extension(sbi_scratch_thishart_ptr(), SBI_HART_EXT_SSTC)) {
#if __riscv_xlen == 32
		csr_write(CSR_STIMECMP, next_event & 0xFFFFFFFF);
		csr_write(CSR_STIMECMPH, next_event >> 32);
#else
		csr_write(CSR_STIMECMP, next_event);
#endif
	} else if (timer_dev && timer_dev->timer_event_start) {
		timer_dev->timer_event_start(next_event);
		csr_clear(CSR_MIP, MIP_STIP);
	}
	csr_set(CSR_MIE, MIP_MTIP);
}
```

可以看到这里有一个 if 逻辑，如果 sbi hart 有 sstc 扩展，则写入 stimecmp csr 寄存器结束，否则调用 timer_dev 的 timer_event_start，而 qemu 和 spike 都在使用的 aclint_mtimer 设备的 timer_event_start 就是在读取 mtimecmp 的地址，所以这部分逻辑是设置 0x2004000 的值的。那么如果 0x2004000 一直是 -1 的话，就说明已经走了 sstc 扩展的 stimecmp 寄存器了。

Sstc 扩展是为了解决每次设置时钟中断都需要进入 sbi 陷入 M 模式设置 mtimecmp 的值导致效率下降的，这个扩展引入了 stimecmp csr 寄存器，同时规定只要 mtime >= stimecmp 直接触发 S 模式时钟中断。这样就避免了从 memory mapping 设置 mtimecmp 再触发 M 态时钟中断后再通过 mideleg 转发到 S 模式的过程，提高了效率。是否启用了 sstc 可以看 OpenSBI 输出的 boot hart isa extensions，如果里面有 sstc 就说明启用了。

而 spike 默认是不开启 sstc 的，但是它也支持，在上面 clint.cc 的 114 行可以看到一个 `hart->state.time->sync(mtime)`，这个函数的内容如下：

```cpp title="(spike) riscv/csrs.cc" linenums="1140"
void time_counter_csr_t::sync(const reg_t val) noexcept {
  shadow_val = val;
  if (proc->extension_enabled(EXT_SSTC)) {
    const reg_t mip_val = (shadow_val >= state->stimecmp->read() ? MIP_STIP : 0) |
      (shadow_val + state->htimedelta->read() >= state->vstimecmp->read() ? MIP_VSTIP : 0);
    const reg_t mask = ((state->menvcfg->read() & MENVCFG_STCE) ? MIP_STIP : 0) | ((state->henvcfg->read() & HENVCFG_STCE) ? MIP_VSTIP : 0);
    state->mip->backdoor_write_with_mask(mask, mip_val);
  }
}
```

所以这个 sync 实际上就是在启用 sstc 的时候检测是否根据 stimecmp 触发时钟中断。spike 上启用 sstc 需要自己设定 isa，即加一个 `--isa=RV64gc_zicntr_sstc`，然后在 GDB 调试的时候 `i r stimecmp` 就能查看到 stimecmp 的值了（qemu 甚至不让看 stimecmp）。

## 参考

- https://openocd.org/doc/html/
- https://tinylab.org/riscv-semihosting/
- https://blog.csdn.net/luolaihua2018/article/details/127344891
- https://zhuanlan.zhihu.com/p/506062424

