---
comment: true
counter: true
---

# Aegisub 自动化

!!! abstract
    即 Aegisub 的自动化脚本，使用 Lua 编写，通过标题栏 自动化 > 自动化 菜单管理脚本（包括载入新的自定义脚本）。

    可以实现通过脚本批量处理字幕内容的效果。

## Lua 速成
Lua 语言语法很简单，写脚本也讲究能用就行，整理了一下基本的 Lua 语法来速成：

- 行尾无分号，缩进不必须，甚至行间可以不用换行，-- 开头为注释
- 动态类型，基本类型有：nil boolean number string function userdata thread table
    - 所有数字类型都是 number，不分整型和浮点型
    - string 可以用单双引号以及双中括号 [[]] 表示
        - 注：Lua 中的 string 其实相当于 bytes，针对 Unicode 字符的话需要另外处理
    - function 也是一个类型，可以作为一个变量来传参之类的
    - table 表也称关联数组，数组字典等都用 table 表示
- 关于变量
    - 不必指定类型，直接赋值即可使用，未赋值的使用时为 nil 而不会报错
    - `#!lua a = 1` 全局变量；`#!lua local a = 1` 局部变量
    - 赋值语句用等号，左右可以是多个变量（逗号分隔）
        - 等号两侧元素个数不同不会报错，会补 nil 或忽略右侧多余值
- 循环
    - `#!lua while (condition) do ... end`
    - `#!lua for var=from,to,step do ... end`
    - `#!lua for i, v in ipairs(table) do ... end`
    - `#!lua repeat ... until (condition)`
    - 可以嵌套，但只有 break 没有 continue
    - continue 可以用 `#!lua goto label` 来实现，label 用 `#!lua ::label::` 定义
- 流程控制
    - `#!lua if (cond1) then ... end`
    - `#!lua if (cond1) then ... else ... end`
    - `#!lua if (cond1) then ... elseif (cond2) then ... end`
    - 可以嵌套，需要注意的是 else 后面不需要 then
- 函数
    - 用 function 定义，可以和变量一样指定全局（默认）或局部（加 local）
        ```lua
        function add(a, b)
            return a + b
        end
        ```
    - 输入输出类型都不用指定，返回直接 return 即可，可以返回多个值
    - 调用时参数个数不同不会报错，多余的参数会被忽略，不足的参数会补 nil
    - 调用时可以省略括号
- 运算符
    - 算数：+ - * / %，^ 乘方，// 整除
    - 逻辑：== ~= > < >= <= and or not
    - a .. b 字符串连接；#a 字符串或表的长度
    - 会进行类型转换，比如 1 + "2" 会得到 3
- 字符串
    - string.len(str) 字节长度，utf8.len(str) 字符长度
    - string.gsub .find .gmatch .match 可以模式匹配（阉割版正则）
    - string.upper .lower .reverse .rep .char .byte .sub 一些看名字就知道用法的函数
    - string.format 格式化，类似 C 的 printf
        - %c %d %s 等（o 八进制，u 无符号，x 十六进制，e 科学计数法，f 浮点数等）
    - 拼接用 ..，不能用 +（会一律尝试转 number）
- table
    - 数组也是 table，下标从 1 开始
    - table.concat(t, sep) 相当于 python sep.join(t)
    - table.insert .remove .sort
    - 未定义的键访问得到 nil，不会报错，值设为 nil 相当于删除
    - t[i] t.i gettable_event(t, i) 都可以访问元素
- 模块
    - 文件内创建一个 table `#!lua module = {}`，然后定义 module.func 等
    - 文件末尾 return module 即相当于一个模块
    - 引用时 require "module" 即可使用 module.func

## 自动化脚本框架
自动化 > 自动化 这个脚本管理器可以直接加载 lua 代码（全局/仅当前 ass）。Aegisub 有两种自动化脚本类型：

- 宏，即通过自动化菜单中点击调用，通过 register_macro 注册
- 导出滤镜，在 Export As 导出脚本时可选择启用滤镜，通过 register_filter 注册

所以简单来讲一个自动化脚本的结构可以是：

```lua
script_name = "..."
script_description = "..."
script_author = "..."
script_version = "..."
-- 上面这些是脚本元数据，aegisub 会读取并显示在菜单中

include("unicode.lua")

function macro_function(subtitles, selected_lines, active_line)
    -- do something
end

aegisub.register_macro(script_name, script_description, macro_function)
```

**aegisub.register_macro(name, desc, func, validator, is_active_func)**
:   - name：脚本名称，显示在自动化菜单里，如果有 / 则分割为子菜单栏
    - desc：脚本描述，鼠标悬浮时显示
    - func：点击脚本名称时调用的函数，会传入以下三个参数
        - subtitles：全部字幕行，可以修改
        - selected_lines：选中的字幕行，一个 table，可以遍历，元素是 subtitles 中编号
        - active_line：当前行，一个 number
    - validator：脚本校验函数，返回 true/false，如果返回 false 则不可用，参数同 func
    - is_active_func：是否活跃，类似 validator，不常用

**aegisub.register_filter(name, desc, priority, func, panel_provider)**
:   - name desc 和 macro 一样
    - priority：选中多个滤镜时的应用优先级，越大越优先
    - func：施加滤镜时调用的函数，传入两个参数
        - subtitles：全部字幕行
        - settings：来自 panel 的设置，没有 panel 则空
    - panel_provider：一个函数，用来定义配置面板

**aegisub.set_undo_point(name)**
:   设置撤销点，name 为撤销点名称，可以在撤销历史中看到，Ctrl-Z 撤销函数效果。

**aegisub.cancel()**
:   取消当前操作，回滚所有更改。

???+ example "Aegisub 自带示例"
    看自带的脚本示例更清晰，比如在每行前加 {\\be1} 标签：

    ```lua
    local tr = aegisub.gettext

    script_name = tr"Add edgeblur"
    script_description = tr"A demo macro showing how to do simple line modification in Automation 4"
    script_author = "Niels Martin Hansen"
    script_version = "1"

    function add_edgeblur(subtitles, selected_lines, active_line)
        for z, i in ipairs(selected_lines) do
            local l = subtitles[i]
            l.text = "{\\be1}" .. l.text
            subtitles[i] = l
        end
        aegisub.set_undo_point(script_name)
    end

    aegisub.register_macro(script_name, tr"Adds \\be1 tags to all selected lines", add_edgeblur)
    ```

    其中 tr 即 aegisub.gettext 用来国际化，自己用可有可无。

## API 及部分自带模块
### subtitles API
传入的 subtitles 是所有行，不仅包括字幕行（[Events]），还有脚本信息行（[Script Info]）和样式行（[V4+ Styles]），所以索引既不是字幕行的行号，也不是 ass 文件中的物理行号。总行数可以用 #subtitles 读取。

#### subtitles 操作
在 macro function 中 subtitles 是可修改的，而 validator 一类中是只读的。有以下操作：

- 读取行：`#!lua line = subtitles[i]`，line 为一个 table，内容下面介绍
- 附加行：添加到文件末尾
    - `#!lua subtitles[0] = line` 索引 0 就表示附加
    - `#!lua subtitles.append(line1, line2, ...)` 可以添加多行
- 插入行：在原第 i 行前插入新行
    - `#!lua subtitles[-i] = line` 索引负数表示插入
    - `#!lua subtitles.insert(i, line1, line2, ...)`
- 替换行：`#!lua subtitles[i] = line`
- 删除行：
    - `#!lua subtitles[i] = nil`
    - `#!lua subtitles.delete(i1, i2, ...)`
    - `#!lua subtitles.delete({i1, i2, ...})`
    - `#!lua subtitles.deleterange(a, b)` 闭区间行号

#### subtitles 行数据
读取到的 subtitles 每一行 line 是一个 table，包含以下键：

- class：一个 string，表示类型，包括 info style dialogue unknown
- raw：一个 string，表示在 ass 文件中对应行的原始内容
- section：一个 string，表示在 ass 文件中所属的部分（"[Script Info]" 一类）
- 不同类型的特定内容：
    - info 类型：
        - key 和 value，都是 string，当前行的信息
    - style 类型：
        - name fontname fontsize bold italic 等样式设置
        - color1 color2 color3 color4 等颜色，可用 extract_color 解析读取
    - dialogue 类型：
        - comment：一个 boolean，表示是否是注释行
        - layer start_time end_time style actor effect 等字幕行设置
        - margin_l ..._r ..._t ..._b：覆盖的 margin，为 0 则表示用 style 默认的
        - text：字幕内容

### 其他常用 API

**aegisub.progress.set(percent)**
:   设置执行进度条的百分比（0-100）。

**aegisub.progress.task(fmt_str, ...)**
:   在进度条下面显示当前正在执行的任务，参数第一个是格式化字符串，后面是格式化的参数。

**aegisub.progress.title(fmt_str, ...)**
:   设置进度窗口的标题，也是利用 string.format。

**aegisub.progress.is_cancelled()**
:   返回一个 boolean 表示用户是否点击了进度窗口中的取消按钮。

**aegisub.debug.out(level, fmt_str, ...)**
:   用于输出，可以写为 aegisub.log，level 可以省略（省略的话则始终显示）。

    level 0-5 依次表示 fatal error warning hint debug trace，在 Preferences 里面可以选择自动化显示的输出等级。

**aegisub.text_extends(style, text)**
:   根据样式获取文字渲染后的信息，style 是一个 table（subtitles API 中的那样），text 是 string。返回以下四个数字（像素为单位）：

    - width height：文字渲染后的宽高
    - descent ext_lead：文字渲染后的 descent 和 leading

**aegisub.frame_from_ms(ms) / aegisub.ms_from_frame(frame)**
:   根据视频的帧速率将毫秒和帧号相互转换。没有帧速率相关信息的时候返回 nil。

**aegisub.video_size()**
:   返回四个值：

    - xres yres：分辨率（像素单位）
    - ar artype：宽高比，artype 为 0 方形、1 为 4:3、2 为 16:9、3 为 2.35、4 为 ar 表示的宽高比

**aegisub.keyframes()**
:   获取关键帧帧号表，即一个排序好的数组。未加载关键帧则为空。

### util 模块
通过 `#!lua include("util.lua")` 或者 `#!lua util = require "aegisub.util"` 引入。

- 表拷贝相关
    - `#!lua util.copy(t)` 返回一个表的浅拷贝
    - `#!lua util.deep_copy(t)` 返回一个表的深拷贝
- 颜色相关
    - `#!lua util.ass_color(r, g, b)` 返回 ass 颜色字符串
    - `#!lua util.ass_style_color(r, g, b, a)` 返回 ass 样式的颜色字符串
    - `#!lua util.ass_alpha(a)` 返回 alpha 字符串（&HAA&）
    - `#!lua util.extract_color(str)` 根据字符串解析颜色
        - 返回四个值分别表示 r g b a
        - 可以解析 ass 样式颜色、行内颜色、行内透明度以及 #RRGGBBAA 格式的字符串
        - 样式内不包含的部分返回 0，解析错误返回 nil
    - `#!lua util.alpha_from_style(str)` extract_color 和 ass_alpha 组合
    - `#!lua util.color_from_style(str)` extract_color 和 ass_color 组合
    - `#!lua util.HSV_to_RGB(h, s, v)` h 在 [0, 360)、s v 在 [0, 1]，返回 r g b 在 [0, 256)
    - `#!lua util.interpolate_color(t, color1, color2)` 在颜色间插值，t 在 [0, 1] 范围内，color1 color2 和返回值都是颜色字符串
    - `#!lua util.interpolate_alpha(t, alpha1, alpha2)` 在透明度间插值，同上
- 字符串扩展
    - `#!lua util.trim(str)` 移除首尾空格
    - `#!lua util.headtail(str)` 按照第一个空格分割，返回前后两个部分字符串
    - `#!lua util.words(str)` 返回迭代器，相当于用 headtail 多次（即 split）
    - 以上字符串扩展都可以将 util 改为 string
- 数学函数
    - `#!lua util.clamp(val, min, max)` 将 val 约束在 min 到 max 间
    - `#!lua util.interpolate(t, a, b)` 在 [a, b] 间插值，t 为比例在 [0, 1] 范围内

### unicode 模块
Lua 的 string 是字节序列，aegisub 提供了 unicode 模块来处理 UTF-8 字符串。通过 `#!lua include("unicode.lua")` 或者 `#!lua unicode = require "aegisub.unicode"` 引入。

- `#!lua unicode.charwidth(str, index)` 字符串 str 第 index 开始的字节表示的字符所占字节数
- `#!lua unicode.chars(str)` 返回迭代器，用来遍历 UTF-8 字符串内所有字符
- `#!lua unicode.len(str)` 字符个数
- `#!lua unicode.codepoint(str)` str 中首字符的码位
- `#!lua unicode.to_upper_case(str) .to_lower_case .to_fold_case`

### clipboard 模块
通过 `#!lua include("clipboard.lua")` 或者 `#!lua clipboard = require "aegisub.clipboard"` 引入。

- `#!lua clipboard.set(str)` 设置剪贴板内容，成功返回 true 否则返回 false
- `#!lua clipboard.get()` 获取剪贴板内容，不包含文本或发生错误返回 nil

### re 模块
Lua string 的模式匹配功能较少，re 模块封装了 boost::regex 实现 PRCE 标准的正则表达式。通过 `#!lua include("re.lua")` 或者 `#!lua re = require "aegisub.re"` 引入。但实际感觉其实也并不好用，这里就不写了。

