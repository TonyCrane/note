---
counter: True
comment: True
---

# mkdocs 源码剖析

!!! abstract
    源项目地址：[:material-github: mkdocs/mkdocs](https://github.com/mkdocs/mkdocs)

    剖析时 sha 值：[`730da08158`](https://github.com/mkdocs/mkdocs/tree/730da08158b05374c4230f9785dd7f5068801fe3)

## 包配置、入口点
### 包配置
一些基础配置不必说，主要是 entry_points 配置：
```python
setup(
    ...
    entry_points={
        'console_scripts': [
            'mkdocs = mkdocs.__main__:cli',
        ],
        'mkdocs.themes': [
            'mkdocs = mkdocs.themes.mkdocs',
            'readthedocs = mkdocs.themes.readthedocs',
        ],
        'mkdocs.plugins': [
            'search = mkdocs.contrib.search:SearchPlugin',
        ],
    },
    ...
)
```
可见创建了三个 entry_points：

- CLI 命令 mkdocs，入口点 mkdocs.\_\_main\_\_:cli
- mkdocs.themes，用于接入外部包定义的主题
- mkdocs.plugins，用于接入外部包定义的插件

### 入口点
命令行的入口点为 mkdocs.\_\_main\_\_:cli。下分析 \_\_main\_\_.py：

- log 相关：
    - 一个自定义的 ColorFormatter（~~我不是很喜欢这个样式，可以改掉~~）
    - 一个 State 用于维护不同命令的 log level（后有 `#!python click.make_pass_decorator(State, ensure=True)`）
- cli 相关：
    - 利用 click 库
    ```python
    @click.group(context_settings={'help_option_names': ['-h', '--help']}) # 设置 help 命令
    @click.version_option( # 设置 version 命令和显示信息
        __version__,
        '-V',
        '--version',
        message=f'%(prog)s, version %(version)s from { PKG_DIR } (Python { PYTHON_VERSION })',
    )
    @common_options # 通用设置
    def cli(): # 命令行主命令 mkdocs
        """
        MkDocs - Project documentation with Markdown.
        """
    ```
    - 一些子命令，选项添加与上面类似，不赘述
        - serve 子命令：调用 mkdocs.commands.serve.serve 函数
        - build 子命令：处理 config（在 mkdocs.config 模块中详细定义）、启动插件、调用 mkdocs.commands.build.build 函数，未失败则运行后关闭插件
        - gh-deploy 子命令：在 build 后调用 mkdocs.commands.gh_deploy.gh_deploy
        - new 子命令：调用 mkdocs.commands.new.new 函数

## 包结构分析
除去 tests 和其它冗余代码后，大致分析的整个包结构：
```text
mkdocs
├── __init__.py         # 定义了版本号
├── __main__.py         # CLI 入口点
├── commands            # CLI 定义
│   ├── __init__.py     
│   ├── babel.py        # 处理语言文件（不是 CLI 命令）
│   ├── build.py        # 构建文档（mkdocs build）
│   ├── gh_deploy.py    # 部署到 Pages（mkdocs gh-deploy）
│   ├── new.py          # 创建新项目（mkdocs new）
│   ├── serve.py        # 开启本地预览服务（mkdocs serve）
│   └── setup.py                # 目测没用？
├── config
│   ├── __init__.py         # 只导出 base 和 config_options
│   ├── base.py             # 基础配置
│   ├── config_options.py   # 各种参数以及验证方式
│   └── defaults.py         # 默认配置
├── contrib
│   ├── __init__.py
│   └── search
│       ├── __init__.py
│       ├── lunr-language
│       │   └── ...
│       ├── prebuild-index.js
│       ├── search_index.py
│       └── templates
│           └── search
│               ├── lunr.js
│               ├── main.js
│               └── worker.js
├── exceptions.py       # 一些定义的异常
├── livereload
│   └── __init__.py     # 本地预览自动刷新服务
├── localization.py     # 本地化相关代码
├── plugins.py          # 插件管理
├── structure           # 页面结构
│   ├── __init__.py
│   ├── files.py
│   ├── nav.py
│   ├── pages.py
│   └── toc.py
├── templates
│   └── sitemap.xml
├── theme.py            # 主题类
├── themes
│   └── ...
└── utils
    ├── __init__.py
    ├── babel_stub.py
    ├── filters.py
    └── meta.py
```

## 一些工具性代码
和运行主逻辑无大关系的一些代码：

### exceptions.py
定义了五个异常类：

- 基类 MkDocsException，不会直接使用。继承自 ClickException，使 click 能够处理并显示
- Abort，终止执行，可以带有信息
- ConfigurationError，由于配置文件原因导致的错误
- BuildError，构建过程中出现的错误，mkdocs 源码中并未直接抛出此类错误，但有子类 PluginError，应该是给第三方插件使用的
- PluginError，在插件中可以抛出的异常，继承自 BuildError

### utils

## build 流程
从 mkdocs build 这一命令的执行流程来逐步自顶向下分析


首先从 \_\_main\_\_.py 进入，调用到 build_command 函数：
```python title="__main__.py" linenums="237"
@cli.command(name="build")
@click.option('-c', '--clean/--dirty', is_flag=True, default=True, help=clean_help)
@common_config_options
@click.option('-d', '--site-dir', type=click.Path(), help=site_dir_help)
@common_options
def build_command(clean, **kwargs):
    """Build the MkDocs documentation"""
    from mkdocs.commands import build

    _enable_warnings()
    cfg = config.load_config(**kwargs)
    cfg['plugins'].run_event('startup', command='build', dirty=not clean)
    try:
        build.build(cfg, dirty=not clean)
    finally:
        cfg['plugins'].run_event('shutdown')
```
其中 common_options 和 common_config_options 装饰器定义为：
```python title="__main__.py" linenums="182"
common_options = add_options(quiet_option, verbose_option)
common_config_options = add_options(
    click.option('-f', '--config-file', type=click.File('rb'), help=config_help),
    # Don't override config value if user did not specify --strict flag
    # Conveniently, load_config drops None values
    click.option('-s', '--strict', is_flag=True, default=None, help=strict_help),
    click.option('-t', '--theme', type=click.Choice(theme_choices), help=theme_help),
    # As with --strict, set the default to None so that this doesn't incorrectly
    # override the config file
    click.option(
        '--use-directory-urls/--no-directory-urls',
        is_flag=True,
        default=None,
        help=use_directory_urls_help,
    ),
)
```
也就是增加了 -q -v -f -s -t --use-directory-urls/--no-directory-urls 这些命令行参数（也会传到 kwargs 中）

_enable_warnings() 可以不用管。之后的流程就是：

1. 调用 config.load_config 加载配置
2. 从配置中找到插件，并触发其 startup 事件
3. 尝试调用 build.build 函数构建文档
    - 若不成功则直接挂掉程序
    - 若成功则触发插件的 shutdown 事件，运行结束

### 加载配置

config/base.py 中 261 行开始的函数 load_config（删除了注释和一些空行）：
```python title="config/base.py"
def load_config(config_file: Optional[Union[str, IO]] = None, **kwargs) -> Config:
    options = kwargs.copy()
    for key, value in options.copy().items():
        if value is None:
            options.pop(key)
    with _open_config_file(config_file) as fd:
        options['config_file_path'] = getattr(fd, 'name', '')
        from mkdocs.config import defaults
        cfg = Config(schema=defaults.get_schema(), config_file_path=options['config_file_path'])
        cfg.load_file(fd)
    cfg.load_dict(options)
    errors, warnings = cfg.validate()
    for config_name, warning in warnings:
        log.warning(f"Config value: '{config_name}'. Warning: {warning}")
    for config_name, error in errors:
        log.error(f"Config value: '{config_name}'. Error: {error}")
    for key, value in cfg.items():
        log.debug(f"Config value: '{key}' = {value!r}")
    if len(errors) > 0:
        raise exceptions.Abort(f"Aborted with {len(errors)} Configuration Errors!")
    elif cfg['strict'] and len(warnings) > 0:
        raise exceptions.Abort(
            f"Aborted with {len(warnings)} Configuration Warnings in 'strict' mode!"
        )
    return cfg
```

这个函数中的流程：

1. 将 kwargs 拷贝到 options 中（也就是通过命令行传入的参数）并删掉值为 None 的配置
2. 通过 \_open\_config\_file 这个上下文管理器来打开配置文件，然后：
    1. 获取实际使用的配置文件路径名，并存到 options 中
    2. 根据 defaults 创建一个 Config 名叫 cfg，其配置文件路径为上面获得到的文件名
    3. 将配置文件中的配置载入 cfg
3. 将命令行参数 options 载入 cfg（此时有覆盖，即命令行配置优先级高于配置文件）
4. 检查 cfg 配置中是否有非法信息
    - 以 debug level 输出所有配置项
    - 如果有非法配置的话输出全部 warnings 和 errors
    - 如果有 error，则直接 abort
    - 如果有 warning，且开启了 strict 模式，也直接 abort
5. 返回得到的 cfg 配置实例

其中的一些细节：
#### \_open\_config\_file
是用 contextmanager 装饰器包装得到的上下文管理器，其接收一个参数 config_file，是从命令行 --config-file 参数获得的配置文件路径，如果运行时没有这一参数则 config_file 为 None。其内部流程：

1. 如果 config_file 为 None（即未指定），则默认尝试读取当前文件夹下的配置文件 mkdocs.yml 或 .yaml
2. 如果 config_file 为字符串，则尝试读取该字符串指定的文件
3. 如果 config_file 是文件对象
    - 如果文件是开启的，则直接将文件指针移到开头
    - 如果文件时关闭的，则获取名称，打开文件
4. 读取完成后，关掉文件

#### 创建 Config、载入配置
Config 是一个基于 UserDict 的类，即可以直接通过 [] 来读取其中 .data 属性（字典）中的值，其在初始化时发生了下面几件事：

1. 从参数设置 _schema，即从 defaults 中读取到的默认参数部分。以及 \_schema\_keys
2. 设置 config_file_path（会自动解码 bytes 类型）
3. 创建 .data 字典属性，以及一个空的 user_configs 列表，里面存放载入的字典原数据
4. 调用 set_defaults 方法设置默认值
    - 即从 schema 中读取设置

在调用 load_file 方法时实际上会读取 yaml 文件内容，解析成字典然后调用 load_dict 方法。调用 load_dict 方法时先将传入的内容直接添加到 user_configs 列表中，然后用其 update data 属性

#### 验证 Config
调用 Config.validate 验证有以下几步：

1. 调用 \_pre\_validate() 方法
    - 其会遍历 \_schema 每一个键值对，调用 config_option 上的 pre_validation 方法，具体由实际子类进行实现
2. 调用 \_validate() 方法
    - 也会遍历 \_schema 每一个键值对，但此时会将键在 config 中对应的值传入 config_option 的 validate 方法（由子类的 run_validation 方法实现，返回一个修正后的值，重新赋值回来
    - 除此之外还会检查不在 \_schema\_keys 中的键，并抛出警告
3. 如果前面都没有出现 error，则调用 \_post\_validate 方法
    - 同 pre，只不过对 config_option 调用的方法从 pre 换成了 post

具体的各个参数的定义和验证方法都在 config/config_options.py 中，很详细易懂

### 触发 Plugin 事件
在前面 ConfigOptions 中有一个 Plugins 子类，来存放插件相关对象，其初始化时会调用 plugins.get_plugins() 函数来全局检查安装的包的 entry_points 是否含有 mkdocs.plugins，来得到一个 Dict[str, EntryPoint] 类型的 installed_plugins 属性（即通过包名映射到插件入口点，即插件类）

这个 Plugins 类在上面所说的 run_validation 过程中会将插件名传入 load_plugin 方法（里面会检查是否安装等一系列问题），并返回得到插件类，统一收集到 plugins.PluginCollection 类中。

在为 PluginCollection setitem 的时候会将插件的所有 on\_ 开头的方法都注册为 event（如 on_startup 方法会注册一个名为 startup 的 event），在调用 run_event("startup") 的时候会调用所有有 on_startup 方法的插件的这一方法，从而执行插件自定义的初始化代码（同时可以根据传入的 command，如 "build"、"gh-deploy"、"serve" 来特判执行不同动作）

### 调用 build 函数构建文档