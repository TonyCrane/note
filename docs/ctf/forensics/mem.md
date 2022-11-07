---
counter: True
comment: True
---

# 内存取证

!!! abstract 
    其实也没系统学习过内存取证方法，做了几道题反正就是 strings 一把梭，不行就 volatility 一把梭（~~再不行就开摆~~）

## strings
dump 出来的内存中往往会存在一些字符串，可以用 strings 命令提取出来，然后通过搜索来寻找一些特定的字符串，比如 flag、secret 啥的。（反正就嗯看嗯搜就完事

## volatility
### 版本与安装
现存的两个版本 volatility2 和 volatility3，分别用了 python2 和 python3。不过 volatility3 感觉不好用，还得是 2

volatility2 安装直接看文档就好，mac 的话有一些依赖包有编译问题，懒得搞，可以去官网下载编译好的二进制包拿来直接运行

### 系统版本与 profile
volatility 的话直接无脑梭就完事了，Windows 的话有内置 profile 可以直接梭，Linux 的话要先找一下版本然后构造对应 profile

查看系统版本：
```shell
volatility -f <file> imageinfo
```

### Windows 取证一把梭
进程相关：
```shell
volatility -f <file> --profile=<profile> pslist
volatility -f <file> --profile=<profile> psxview
volatility -f <file> --profile=<profile> psscan
volatility -f <file> --profile=<profile> pstree
volatility -f <file> --profile=<profile> memdump -p <PID> --dump-dir=./
```

命令相关：
```shell
volatility -f <file> --profile=<profile> cmdscan
volatility -f <file> --profile=<profile> consoles
volatility -f <file> --profile=<profile> cmdline
```

文件相关：
```shell
volatility -f <file> --profile=<profile> filescan
volatility -f <file> --profile=<profile> filescan > files.txt
volatility -f <file> --profile=<profile> dumpfiles -Q <virtual addr> --dump-dir=./ # 由 filescan 结果来定
volatility -f <file> --profile=<profile> mftparser > mftparser.txt # 一些 filescan 搜不出来/被删了的可以尝试 mtfparser
```

其它一堆操作：
```shell
volatility -f <file> --profile=<profile> envars
volatility -f <file> --profile=<profile> netscan
volatility -f <file> --profile=<profile> connscan
volatility -f <file> --profile=<profile> svcscan
volatility -f <file> --profile=<profile> privs
volatility -f <file> --profile=<profile> hivelist
volatility -f <file> --profile=<profile> printkey -K "SAM\Domains\Account\Users\Names"
volatility -f <file> --profile=<profile> iehistory
volatility -f <file> --profile=<profile> notepad
volatility -f <file> --profile=<profile> editbox
volatility -f <file> --profile=<profile> userassist
volatility -f <file> --profile=<profile> clipboard -v
```

### Linux 取证
Linux 首先需要构造一下 profile。volatility3 -f <file> banners 可以检测当前 Linux 版本。

然后在对应系统内进入 volatility 的 tools/linux 目录，执行 make，得到 module.dwarf 文件。除此之外还需要 /boot 目录下的 System.map 文件，然后将这两个文件打包压缩，放在 volatility/plugins/overlays/linux 目录下即可，再执行 volatility --info 就可以看到新的 Linux profile 了。

通过 volatility --info | grep linux_ 可以找到所有 Linux 内存下可用的指令，逐个试着用即可：

??? example "plugins list"
    ```text
    linux_apihooks             - Checks for userland apihooks
    linux_arp                  - Print the ARP table
    linux_aslr_shift           - Automatically detect the Linux ASLR shift
    linux_banner               - Prints the Linux banner information
    linux_bash                 - Recover bash history from bash process memory
    linux_bash_env             - Recover a process' dynamic environment variables
    linux_bash_hash            - Recover bash hash table from bash process memory
    linux_check_afinfo         - Verifies the operation function pointers of network protocols
    linux_check_creds          - Checks if any processes are sharing credential structures
    linux_check_evt_arm        - Checks the Exception Vector Table to look for syscall table hooking
    linux_check_fop            - Check file operation structures for rootkit modifications
    linux_check_idt            - Checks if the IDT has been altered
    linux_check_inline_kernel  - Check for inline kernel hooks
    linux_check_modules        - Compares module list to sysfs info, if available
    linux_check_syscall        - Checks if the system call table has been altered
    linux_check_syscall_arm    - Checks if the system call table has been altered
    linux_check_tty            - Checks tty devices for hooks
    linux_cpuinfo              - Prints info about each active processor
    linux_dentry_cache         - Gather files from the dentry cache
    linux_dmesg                - Gather dmesg buffer
    linux_dump_map             - Writes selected memory mappings to disk
    linux_dynamic_env          - Recover a process' dynamic environment variables
    linux_elfs                 - Find ELF binaries in process mappings
    linux_enumerate_files      - Lists files referenced by the filesystem cache
    linux_find_file            - Lists and recovers files from memory
    linux_getcwd               - Lists current working directory of each process
    linux_hidden_modules       - Carves memory to find hidden kernel modules
    linux_ifconfig             - Gathers active interfaces
    linux_info_regs            - It's like 'info registers' in GDB. It prints out all the
    linux_iomem                - Provides output similar to /proc/iomem
    linux_kernel_opened_files  - Lists files that are opened from within the kernel
    linux_keyboard_notifiers   - Parses the keyboard notifier call chain
    linux_ldrmodules           - Compares the output of proc maps with the list of libraries from libdl
    linux_library_list         - Lists libraries loaded into a process
    linux_librarydump          - Dumps shared libraries in process memory to disk
    linux_list_raw             - List applications with promiscuous sockets
    linux_lsmod                - Gather loaded kernel modules
    linux_lsof                 - Lists file descriptors and their path
    linux_malfind              - Looks for suspicious process mappings
    linux_memmap               - Dumps the memory map for linux tasks
    linux_moddump              - Extract loaded kernel modules
    linux_mount                - Gather mounted fs/devices
    linux_mount_cache          - Gather mounted fs/devices from kmem_cache
    linux_netfilter            - Lists Netfilter hooks
    linux_netscan              - Carves for network connection structures
    linux_netstat              - Lists open sockets
    linux_pidhashtable         - Enumerates processes through the PID hash table
    linux_pkt_queues           - Writes per-process packet queues out to disk
    linux_plthook              - Scan ELF binaries' PLT for hooks to non-NEEDED images
    linux_proc_maps            - Gathers process memory maps
    linux_proc_maps_rb         - Gathers process maps for linux through the mappings red-black tree
    linux_procdump             - Dumps a process's executable image to disk
    linux_process_hollow       - Checks for signs of process hollowing
    linux_psaux                - Gathers processes along with full command line and start time
    linux_psenv                - Gathers processes along with their static environment variables
    linux_pslist               - Gather active tasks by walking the task_struct->task list
    linux_pslist_cache         - Gather tasks from the kmem_cache
    linux_psscan               - Scan physical memory for processes
    linux_pstree               - Shows the parent/child relationship between processes
    linux_psxview              - Find hidden processes with various process listings
    linux_recover_filesystem   - Recovers the entire cached file system from memory
    linux_route_cache          - Recovers the routing cache from memory
    linux_sk_buff_cache        - Recovers packets from the sk_buff kmem_cache
    linux_slabinfo             - Mimics /proc/slabinfo on a running machine
    linux_strings              - Match physical offsets to virtual addresses (may take a while, VERY verbose)
    linux_threads              - Prints threads of processes
    linux_tmpfs                - Recovers tmpfs filesystems from memory
    linux_truecrypt_passphrase - Recovers cached Truecrypt passphrases
    linux_vma_cache            - Gather VMAs from the vm_area_struct cache
    linux_volshell             - Shell in the memory image
    linux_yarascan             - A shell in the Linux memory image
    ```

不过做题感觉来说对 Linux 用 volatility 没有对 Windows 用好用。