---
comment: true
counter: true
---

# Aegisub 卡拉 OK 特效模板

!!! abstract
    ass 字幕内的 k 轴效果非常有限，通过 Aegisub 自带的 kara-templater 自动化脚本配合一些模板行可以实现 k 轴部分的替换，以实现更丰富的效果。

## 卡拉 OK 标签（k 轴）

有 \k \kf（同 \K）\ko 三种行内特效标签，一句打好的 k 轴类似如下格式：

```
{\k56}a{\k55}b{\k56}c{\k55}d{\k56}e{\k55}f{\k56}g{\k55}h{\k56}i
```

被 \k 系列特效标签分隔的称为音节（syllable），每个音节前面的 {\k<number\>} 表示该音节持续的时间，以厘秒（百分之一秒）为单位。这个轴可以使用 Aegisub 带的卡拉 OK 模式来打。

默认的三种 k 标签的效果如下：

- \k 已经开始的音节显示为主要颜色，未开始的音节显示为次要颜色（突变）
- \kf \K 在音节的时间范围内从左到右从次要颜色变为主要颜色
- \ko 和 \k 的差别在于未开始的音节无边框

可见默认的效果非常少，但如果能将每个音节到来的时间等计算出来，再配合 \t 动画标签等自动化地填充到音节前，就可以实现一些更复杂的效果了。Aegisub 的 kara-templater 自动化脚本就是进行这个工作，还附带了执行 lua 脚本等功能。

## 特效模板基本工作原理
kara-template 主要根据每一字幕行的 Effect 即特效部分来识别与其相关的特效行。主要分为两大类：

- template 行：特效部分按空格分隔第一个单词为 template，且该行标记为注释
- code 行：特效部分按空格分隔第一个单词为 code，且该行标记为注释

因为标记为了注释，所以在渲染时不会有任何作用，它们的用处只有在执行 kara-templater 脚本时被读取。

这两种特效行的效果或者说用处是：

- template：模板，顾名思义它会用来替换所有 {\k<number\>} 标签
- code：代码，不会进行实际的替换，但里面的 lua 代码会被执行，一般用来定义一些变量/函数留到 template 中使用

那它们肯定也不会残暴地替换整个 ass 文件中的所有带 k 轴的部分，它们的作用范围是**仅和它们属于相同样式的字幕行**，且这个行有两种情况：

- Effect 部分为空且不是注释行
- Effect 部分为 karaoke 或者 Karaoke，不论是不是注释行

也就是说在执行 kara-templater 脚本时，会先收集字幕中的全部 template 和 code，然后处理按照上述规则匹配的行，对于每一个需要处理的行按顺序依次执行 template 或 code（顺序就是在文件中出现的顺序），对于 code 就放到 lua 环境中执行，对于 template：

- 生成一个新的行，特效标记为 fx，将原字幕中的 k 标签逐个替换为 template 行内容
- 处理好后将原字幕行标记为注释，将特效设置为 karaoke

这样的效果就是再次执行脚本的时候所有特效为 fx 的行会被删除，然后特效为 karaoke 的注释行会用来生成新的 fx 行，以达到更新的效果。

## 特效模板详细用法
### 模板修饰语
只有 template 和 code 两种还是太少了，但作为基本功能还是够的（一个实际替换，一个作准备）。所以加了修饰语的概念，让这二者的效果有了更多种的变化。

在没有修饰语的情况下，template 默认带 syl，code 默认带 once。

**once**
:   只能用在 code 后，表示这个代码在脚本运行时只执行一次，且最先执行。

**line *name***
:   code line 表示每行都会执行这个代码。

    template line 表示模板作用在行上，即一行 k 轴生成一行 fx 轴，其中的 \k 标签被替换为模板内容。template line 后可加一个 *name*，带有相同 *name* 的行模板会拼到一起作用。

    ??? example
        |Effect|Text|
        |:--|:--|
        |template line|A|
        |template line|B|
        |karaoke|{\k56}a{\k55}b|
        |fx|AaAb|
        |fx|BaBb|
        
        |Effect|Text|
        |:--|:--|
        |template line a|A|
        |template line a|B|
        |karaoke|{\k56}a{\k55}b|
        |fx|ABaABb|

**pre-line *name***
:   只能用在 template 上，会在每个原始字幕行前加上模板内容。如果有指定 *name* 则配合对应 *name* 的 template line 一起使用。

    ??? example
        |Effect|Text|
        |:--|:--|
        |template pre-line|C|
        |karaoke|{\k56}a{\k55}b|
        |fx|Cab|
        
        |Effect|Text|
        |:--|:--|
        |template pre-line a|C|
        |template line a|A|
        |karaoke|{\k56}a{\k55}b|
        |fx|CAaAb|

**syl**
:   code syl 表示每个音节都会执行一次代码。

    template syl 表示针对每个音节生成新的一行，将音节前的 \k 标签替换为模板内容也放在生成行的开头。

    ??? example
        |Effect|Text|
        |:--|:--|
        |template syl|A|
        |karaoke|{\k56}a{\k55}b|
        |fx|A|
        |fx|Aa|
        |fx|Ab|

        可以注意到有一行只有 A，这是开头的空音节生成的，后面会讲到可以通过 noblank 修饰语删掉。

**all**
:   code 和 template 都可用，表示在筛选匹配的字幕行时无视样式，即把特效模板用在所有行上（而不仅是相同样式的行上）。

**char**
:   一般用于 template，表示每个字符生成一个新行，并在开头添加模板内容。template syl char 和 template char 效果一样。

**fx *name***
:   用于 template syl，只在匹配到内联特效 *name* 的时候应用模板。

    内联特效为 \\-*name* 这个无实际作用的特效标签。且对后续所有音节都会产生效果。

    ??? example
        |Effect|Text|
        |:--|:--|
        |template syl fx name|A|
        |karaoke|{\k56}a{\k55\\-name}b{\k55}c|
        |fx|Ab|
        |fx|Ac|

**fxgroup *name***
:   用于 template syl，需要配合 code 行来设置 fxgroup，以实现条件判断。

    ??? example
        |Effect|Text|
        |:--|:--|
        |code syl|fxgroup.group = (syl.duration > 1000)|
        |template syl fxgroup group|A|
        |karaoke|{\k56}a{\k55}b{\k200}c|
        |fx|Ac|

**keeptags**
:   用于保留原有的额外标签。

    ??? example
        |Effect|Text|
        |:--|:--|
        |template line keeptags|A|
        |karaoke|{\k56}a{\k55\fs100}b{\k55}c|
        |fx|AaA{\fs100}bAc|

        如果不加 keeptags 则 \fs 会消失。如果用在 template syl 上，则 \fs 只保留一个音节而不会加在后续所有上。

**multi**
:   日语中一个汉字可能有多个音节，如果要为此创建多次效果则需要用 multi，多的音节内容用 # 占位。

    ??? example
        |Effect|Text|
        |:--|:--|
        |template syl multi|A|
        |karaoke|<span style="font-variant-ligatures: none;">{\k56}a{\k55}#{\k55}b</span>|
        |fx|A|
        |fx|Aa|
        |fx|Aa|
        |fx|Ab|

**noblank**
:   不对空音节起作用。

**notext**
:   用在 template 上，生成的新内容不会包含原字幕行中的文本。

    ??? example
        |Effect|Text|
        |:--|:--|
        |template line notext|A|
        |karaoke|{\k56}a{\k55}b|
        |fx|AA|

**repeat *n* / loop *n***
:   将模板重复执行 *n* 次。

### 内联变量
我们的目的是将 \k 替换为更有意义的标签，比如 \t 的动画，那这里就需要时间信息，所以模板的执行环境提供了内联变量供使用。同时也可以使用 !! 包裹里面写 lua 表达式，得到的结果会放回到原位置。

- 行变量
    - 字幕行属性：\$layer \$style \$actor（说话人）\$margin_l ..._r/v/t/b \$li（行号）
    - 时间信息：\$lstart \$lend \$ldur \$lmid，均以毫秒为单位，绝对时间
    - 位置信息：\$lx \$ly \$lleft \$lright \$lcenter \$ltop \$lmiddle \$lbottom \$lwidth \$lheight
    - 音节信息：\$syln，即行内音节个数
- 音节变量
    - 时间信息：\$sstart \$send \$sdur \$smid，均以毫秒为单位，相对于行开始的时间
        - \$skdur 以厘秒为单位（\k 后的原值）
    - 位置信息：\$sx \$sy \$sleft \$sright \$scenter \$stop \$smiddle \$sbottom \$swidth \$sheight
    - 音节信息：\$si，即在行内是第几个音节

时间和位置信息是可适应的，即不写开头的 l 和 s，在 pre-line 中为行变量，其它情况为音节变量。

用法比如 template syl 要保持各音节位置的话，模板里要写 {\\pos(\$x,\$y)}。时间信息可以用在 \\t 标签里。

???+ example "Aegisub 官方文档中的示例"
    一个 template line 行模板，内容：

    ```text
    {\r\k$kdur\t($start,$end,\1c&H00FF00&)\t($start,!$start+$dur*0.3!,\fscy120)\t(!$start+$dur*0.3!,$end,\fscy100)}
    ```

    - `\r`：重置样式，摆脱前面标签的影响
    - `\k$kdur`：保留 \k 标签，即保主次颜色上色的效果
    - `\t($start,$end,\1c&H00FF00&)`：从音节开始到结尾渐变上绿色
    - `\t($start,!$start+$dur*0.3!,\fscy120)`：从音节开头持续音节长度的 30%，呈现拉高 20% 的动画
    - `\t(!$start+$dur*0.3!,$end,\fscy100)`：剩下的 70% 时间内将高度变回原样

### 代码执行环境
即 template 中内联变量/内联 Lua 表达式，以及 code 代码在执行时能接触到的环境。

这部分感觉还是直接看 kara-templater 代码更清晰。这两个特效模板分别通过 run_text_template run_code_template 函数执行。

**run_text_template(template, tenv, varctx)**
:   template 就是模板行内容，tenv varctx 是两个表，分别记录了代码运行环境和内联变量值，执行过程大概是：

    - 匹配 \$ 开头的内联变量，通过 varctx 表查找并用值替代
    - 匹配 !! 中的内容，设置执行环境为 tenv，再调用 pcall，将结果替代回去

**run_code_template(template, tenv)**
:   同上，直接使用 tenv 环境 pcall 代码内容。

可见主要环境有 tenv varctx 两个。而 varctx 就是前面提到的内联变量，所以不必多说，那接下来要关注的就是 tenv。

tenv 会在 apply_templates 开头进行全局可访问模块的设置以及一些函数的定义，然后在 apply_templates 后面遍历匹配行，对匹配到的行调用 apply_line 函数。apply_line 函数中会设置一些针对当前行或者音节的变量。

从简单的来看，行和音节变量：

- line：当前处理的行，和[自动化](automation/)中 subtitles API 中的 line 一样，但会多一些其他参数，可以修改
- orgline：原始行
- syl：当前处理的音节
- basesyl：char 和 multi 修饰语下为原音节，否则和 syl 一样
- meta：脚本元数据，即 [Script Info] 内容，包含 res_x res_y

line 和 syl 是经过了 karaskel.lua 中的一系列处理函数处理过的，会多很多属性，这部分还是参考[官方文档中 karaskel.lua 的部分](https://aegisub.org/docs/3.2/Automation/Lua/Modules/karaskel.lua/index.html#dialogue-line-table)。

接下来看可全局访问的模块，即 apply_templates 开头的代码：

```lua
local tenv = {
    meta = meta,
    string = string,
    math = math,
    _G = _G
}
tenv.tenv = tenv
```

即 string math 两个常用的标准库直接加载进去了。剩下 _G 表示全局变量（类似 python globals()），可以通过 _G.xxx 访问更多标准库或者 Aegisub 的库，比如可以调用 _G.util.interpolate_color 来生成插值渐变色。还有一个 tenv 表示自己。

接下来 apply_templates 函数中定义了一系列函数，可以在 template 和 code 中使用，定义方法大概是：

```lua
tenv.retime = function(mode, addstart, addend)
    ...
end
```

**retime(mode, addstart, addend)**
:   比较重要且常用的一个函数，用来修改生成行的时间。mode 提供一个 start 和 end 的基准，再分别加上 addstart addend 作为新的行时间。有以下 mode：

    - set 或 abs：直接设置行时间为 addstart addend
    - syl：音节的起止时间为基准
    - presyl：基准起止时间都是音节的开始时间
    - postsyl：基准起止时间都是音节的结束时间
    - line：行的起止时间为基准
    - preline：基准起止时间都是行的开始时间
    - postline：基准起止时间都是行的结束时间
    - start2syl：基准起始时间为行的开始时间，结束时间为音节的开始时间
    - syl2end：基准起始时间为音节的结束时间，结束时间为行的结束时间
    - sylpct：基准起止时间都是音节的开始时间，但加的时间是 addstart*syl.duration/100（addend 同理）而不是 addstart

    ??? example
        比如将 template line 的内容设为以下可以延长行的开始和结尾时间各 100ms 并附加其他效果：

        ```text
        !retime("line", -100, 100)!{...}
        ```

**relayer(layer)**
:   将生成行的层设为 layer。

**restyle(style)**
:   将生成行的样式设为 style。注意修改后不会更新内联的位置变量。

**maxloop(maxj) / maxloops(maxj)**
:   设置 template 执行的最多循环次数。

    tenv.j 为当前进行了几次循环，tenv.maxj 为最多进行几次循环停止。尝试进行的循环次数就是修饰语中的 loop *n*。

**loopctl(j, maxj)**
:   同时控制循环中的 j 和 maxj，很少用。

**remember(name, value)**
:   将 value 这个值存储为 name，可以在后面的 template 中通过 recall 函数来得到保存的值。且返回 value 本身，因此可以直接套在裸值上使用。在保存随机值时常用。

**remember_if(name, value, condition)**
:   套一层 if，只有 condition 成立时记录值。

**recall(name, default)**
:   返回保存的值，没有保存则返回 default。

    ??? example "Aegisub 官方文档中的示例"
        ```text
        template syl,{\frz!remember("entryrotation",math.random(100,200))!\fscx300\fscy300\t(0,300,\frz0\fscx100\fscy100)\pos($x,$y)}
        template syl,{\frz-!recall("entryrotation")!\fscx300\fscy300\t(0,300,\frz0\fscx100\fscy100)\pos($x,$y)\fad(300,0)}
        ```

        即通过 math.random 生成一个随机数并记录为 entryrotation，然后在后面的 template 中通过 recall 来获得同一个值。

