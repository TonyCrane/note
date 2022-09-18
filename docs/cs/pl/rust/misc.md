---
counter: True
comment: True
fold_toc: True
---

# Rust 杂项随记

!!! abstract
    看各种文档、教程记录的零散知识点

## 语法/用法补充
- std::mem::size_of_val(&x) 返回 x 占用的空间（以字节为单位）
- .to_string() 方法会利用当前类型上 Display trait 的 fmt 输出，将其转为 String（实现了 Display 就实现了 ToString trait）
- .parse() 会尝试解析字符串到其它类型，如果那个类型实现了 FromStr trait 则可以正常转换返回 Ok(...) 否则返回 Err(...)
    - 已经标注了绑定变量的类型可以直接调用 .parse()
    - 不能推测类型的需要通过 .parse::<*type*>() 进行调用
- ref 可以用来创建引用
    - let ref a = 1; 相当于 let a = &1;
    - match 的时候可以在 pattern 里通过 ref 来创建引用
        ```rust
        let a = 1;
        match a {
            ref b => ..., // b 是一个引用
        }
        match a {
            ref mut b => ..., // b 是一个可变引用
        }
        ```
- 输入输出
    - 利用 Read trait 的方法进行读入，std::io::stdin() 带有 Read trait，可以对其调用 read 方法
    - 也可以调用 std::io::Stdin 上的 read_line 方法
        ```rust
        let mut line = String::new();
        let len_bytes = std::io::stdin().read_line(&mut line).unwrap();
        ```
    - 输出除了通过 print 之外还可以利用 Write trait 的方法，对 std::io::stdout() 调用 .write 方法
    - 文件输入输出通过 std::fs::File::open 打开后同样使用 Read 和 Write 的方法即可


### Reference
<div class="reference" markdown="1">

- [Rust By Example](https://doc.rust-lang.org/stable/rust-by-example/index.html)
- [Rust docs](https://doc.rust-lang.org/std/index.html)

</div>

## Cargo
1. 常规项目布局：
    ```text
    .
    ├── Cargo.lock
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs
    │   ├── main.rs
    │   └── bin/
    │       ├── named-executable.rs
    │       ├── another-executable.rs
    │       └── multi-file-executable/
    │           ├── main.rs
    │           └── some_module.rs
    ├── benches/
    │   ├── large-input.rs
    │   └── multi-file-bench/
    │       ├── main.rs
    │       └── bench_module.rs
    ├── examples/
    │   ├── simple.rs
    │   └── multi-file-example/
    │       ├── main.rs
    │       └── ex_module.rs
    └── tests/
        ├── some-integration-tests.rs
        └── multi-file-test/
            ├── main.rs
            └── test_module.rs
    ```
1. Cargo.toml 与 Cargo.lock
    - Cargo.toml 描述了依赖等元信息，是手动修改的
    - Cargo.lock 是 cargo 自动维护的关于依赖的更多更准确的信息（比如通过 git 下载的包会附带 sha 值），不应该被手动修改
    - lib 包中的 Cargo.lock 应该添加到 .gitignore 中，而 bin 包中的 Cargo.lock 需要附带上传
1. 实用 GitHub Action 脚本

    ??? example "cargo book 中脚本"
        ```yaml
        name: Cargo Build & Test

        on:
          push:
          pull_request:

        env: 
          CARGO_TERM_COLOR: always

        jobs:
          build_and_test:
            name: Rust project - latest
            runs-on: ubuntu-latest
            strategy:
              matrix:
                toolchain:
                  - stable
                  - beta
                  - nightly
            steps:
              - uses: actions/checkout@v3
              - run: rustup update ${{ matrix.toolchain }} && rustup default ${{ matrix.toolchain }}
              - run: cargo build --verbose
              - run: cargo test --verbose
        ```

    ??? example "course.rs 中测试脚本"
        ```yaml
        on: [push, pull_request]

        name: Continuous integration

        jobs:
          check:
            name: Check
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v2
              - uses: actions-rs/toolchain@v1
                with:
                  profile: minimal
                  toolchain: stable
                  override: true
              - run: cargo check

          test:
            name: Test Suite
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v2
              - uses: actions-rs/toolchain@v1
                with:
                  profile: minimal
                  toolchain: stable
                  override: true
              - run: cargo test

          fmt:
            name: Rustfmt
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v2
              - uses: actions-rs/toolchain@v1
                with:
                  profile: minimal
                  toolchain: stable
                  override: true
              - run: rustup component add rustfmt
              - run: cargo fmt --all -- --check

          clippy:
            name: Clippy
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v2
              - uses: actions-rs/toolchain@v1
                with:
                  profile: minimal
                  toolchain: stable
                  override: true
              - run: rustup component add clippy
              - run: cargo clippy -- -D warnings
        ```
1. 指定依赖
    - 默认从 crates.io 上下载，只需要名字和版本号
    - 版本指定
        - 版本号使用 SemVer 规范，即 major.minor.patch
        - 一个版本号规定的是一个版本范围
        - 最低版本是书写出来的版本，最高版本会保证最左侧非零的版本号不变，例：
            ```text
            1.2.3  :=  >=1.2.3, <2.0.0
            1.2    :=  >=1.2.0, <2.0.0
            1      :=  >=1.0.0, <2.0.0
            0.2.3  :=  >=0.2.3, <0.3.0
            0.2    :=  >=0.2.0, <0.3.0
            0.0.3  :=  >=0.0.3, <0.0.4
            0.0    :=  >=0.0.0, <0.1.0
            0      :=  >=0.0.0, <1.0.0
            ```
            - cargo update 也会按照这个规范更新到允许的最高版本（如 0.2.3 如果要更新的话，且 0.2.5 是最新的以 0.2 开头的版本，则只会更新到 0.2.5）
        - 波浪号：
            ```text
            ~1.2.3  := >=1.2.3, <1.3.0
            ~1.2    := >=1.2.0, <1.3.0
            ~1      := >=1.0.0, <2.0.0
            ```
        - 通配符：
            ```text
            *     := >=0.0.0
            1.*   := >=1.0.0, <2.0.0
            1.2.* := >=1.2.0, <1.3.0
            ```
        - 也可以使用大于等于小于号，以及逗号分隔的多个限定写法
    - 更换 registry
        ```toml
        some-crate = { version = "1.0", registry = "my-registry" }
        ```
    - 通过 git 获取
        ```toml
        regex = { git = "https://github.com/rust-lang/regex" }
        regex = { git = "https://github.com/rust-lang/regex", branch = "next" }
        ```
    - 从本地路径获取（相对路径相对于 Cargo.toml）
        ```toml
        some-crate = { path = "..." }
        some-crate = { path = "...", version = "..." }
        ```
        - publish 的话需要先将 some-crate publish
        - 指定了 version 的话 publish 的时候会使用 crates.io 上的这个版本，其它时候使用本地版本
    - 分平台：
        ```toml
        [target.'cfg(windows)'.dependencies]
        inhttp = "0.4.0"

        [target.'cfg(unix)'.dependencies]
        penssl = "1.0.1"

        [target.'cfg(target_arch = "x86")'.dependencies]
        ative-i686 = { path = "native/i686" }

        [target.'cfg(target_arch = "x86_64")'.dependencies]
        ative-x86_64 = { path = "native/x86_64" }
        ```

### Reference
<div class="reference" markdown="1">

- [The Cargo Book](https://doc.rust-lang.org/stable/cargo/index.html)、[中文翻译版 Cargo 手册](https://rustwiki.org/zh-CN/cargo/index.html)

</div>