---
counter: True
comment: True
---

# SVG 

!!! abstract 
    SVG（Scalable Vector Graphics）是一种基于 XML 描述矢量图形的图片格式
    
    现行标准是 {~~SVG 2：https://www.w3.org/TR/SVG/~>SVG 1.1：https://www.w3.org/TR/SVG11/~~}<br/>
    SVG 2 仍在 CR 阶段，区别：https://www.w3.org/TR/SVG/changes.html

    [REC-SVG11-20110816.pdf](https://www.w3.org/TR/SVG11/REC-SVG11-20110816.pdf)

    SVG 标准文档还没有完整读过，这里只是一些在修 manim 的 SVGMobject 的时候学到的 SVG 相关内容


- SVG Namespace: `http://www.w3.org/2000/svg`
- Public Identifier for SVG 1.1: `PUBLIC "-//W3C//DTD SVG 1.1//EN"`
- System Identifier for the SVG 1.1 Recommendation: `http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd`

## 坐标系统
左上角为原点，向右为 x 正方向，向下为 y 正方向

transform 属性会改变元素及其子元素的坐标系

## 常见 EBNF 语法
???+ note "一些 SVG 的 EBNF"
    ```EBNF
    coordinate-pair:
        coordinate comma-wsp coordinate
        | coordinate negative-coordinate
    coordinate:
        number
    number:
        sign? integer-constant
        | sign? floating-point-constant
    negative-coordinate:
        "-" integer-constant
        | "-" floating-point-constant
    comma-wsp:
        (wsp+ comma? wsp*) | (comma wsp*)
    comma:
        ","
    integer-constant:
        digit-sequence
    floating-point-constant:
        fractional-constant exponent?
        | digit-sequence exponent
    fractional-constant:
        digit-sequence? "." digit-sequence
        | digit-sequence "."
    exponent:
        ( "e" | "E" ) sign? digit-sequence
    sign:
        "+" | "-"
    digit-sequence:
        digit
        | digit digit-sequence
    digit:
        "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
    wsp:
        (#x20 | #x9 | #xD | #xA)+
    ```

从后往前来看：

- wsp：空格，包含四种，ASCII 码值为 `0x9, 0x20, 0xA, 0xD`（SVG2 中多了 `0xC`），并且可以连续多个
- digit: 数字字符，0 到 9
- digit-sequence: 数字字符序列，可以为单个或者多个数字字符
- sign: 符号，+ 或 -
- exponent: 指数，e 大小写均可，指数是有符号或者无符号（即正）整数，如 `e2 E+2 E-10` 均为合法 exponent
- fractional-constant: 分数常数，整数部分为 0 可以省略，小数部分为 0 也可以省略，如 `1.2 .3 4.` 可以表示三个分数常数 1.2, 0.3, 4.0
- floating-point-constant: 浮点数常数，可以是 分数常数 / 分数常数加指数 / 整数常数加指数
- integer-constant: 整数常数，即数字字符序列
- comma: 逗号字符 `,`，ASCII 码值 `0x2C`
- comma-wsp: 间隔符，可以是 逗号 / 逗号加任意多空格 / 任意多空格 / 任意多空格加逗号加任意多空格
- negative-coordinate: 负坐标值，可以是 负号加整数常数 / 负号加浮点数常数
- number: 数字，有符号或者无符号（正）的整数常数或者浮点数常数
- coordinate: 坐标值，即数字 number
- coordinate-pair: 坐标，可以是两个用 comma-wsp 分隔的坐标值，第二个坐标值为负的时候可以不进行分隔，即 `1-2` 表示 (1, -2)

## 读取数字的正则表达式
从字符串中读取出上面的 number 可以直接用一个正则来解决：
```regex
[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?
```
![](/assets/images/cs/web/svg/regex.png)
也就是上面的整个逻辑

- 整体可以是 +- 或者不指定：`[-+]?`
- 指数前部分：`(?:\d+(?:\.\d*)?|\.\d+)`
    - 有整数部分：`\d+(?:\.\d*)?`
        - 整数部分：`\d+`
        - 小数部分（可有可无）：`(?:\.\d*)?`
            - 小数点：`\.`
            - 小数部分（可有可无）：`\d*`
    - 无整数部分（即忽略 0）：`\.\d+`
        - 小数点：`\.`
        - 小数部分（一定有）：`\d+`
- 指数部分（可有可无）：`(?:[eE][-+]?\d+)?`
    - 指数标识：`[eE]`
    - 符号（可有可无）：`[-+]?`
    - 指数部分（一定有，且是整数）：`\d+`

为了不捕获 () 中的内容，需要使用 (?:)<br/>
使用的时候直接把匹配到的内容传入 float 即可：
```python
number_pattern = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
numbers = [float(x) for x in number_pattern.findall(number_string)]
```

## <svg\> 元素
在一个 SVG 中，可以有很多 <svg\> 元素，最外层只有一个 <svg\> 元素，内层可以嵌套

svg 规定的元素都在 XML 命名空间 http://www.w3.org/2000/svg 中，所以要规定 `xmlns="http://www.w3.org/2000/svg"`

属性：

version
: 版本号，1.1 / 1.0 

x
: 对于最外层 svg 元素没有作用，对于内层 svg 元素指定边界的左上角的 x 坐标

y
: 对于最外层 svg 元素没有作用，对于内层 svg 元素指定边界的左上角的 y 坐标

width
: 规定宽度，可以是长度或者百分比

height
: 规定高度

## 其他结构元素
- <g\>：即 group，可以有子元素，并且可以有 id 用来引用
- <defs\>：包含一些子元素，用来复用，不直接显示
- <symbol\>：类似 <g\>
- <use\>：复用，通过 `xlink:href` 来指定引用对象，并且可以使用 x, y, style 等一系列属性来规定位置和样式

## 形状元素
|元素|属性|
|:---:|:---:|
|<rect\>|x, y 左上角坐标<br/>width, height 矩形宽高|
|<circle\>|cx, cy 圆心坐标<br/>r 圆半径|
|<ellipse\>|cx, cy 椭圆中心坐标<br/>rx, ry 水平/垂直半径|
|<line\>|x1, y1 起点坐标<br/>x2, y2 终点坐标|
|<polygon\>|points 多边形端点坐标|
|<polyline\>|points 折线端点坐标|
|<path\>|d 路径指令|

### <polygon\> 和 <polyline\> 的 points 语法
???+ note "EBNF 语法"
    它们的 points 属性的值都是 list-of-points 类型
    ```EBNF
    list-of-points:
        wsp* coordinate-pairs? wsp*
    coordinate-pairs:
        coordinate-pair
        | coordinate-pair comma-wsp coordinate-pairs
    ```

由上面的解释同理，这个 EBNF 也非常清晰

- coordinate-pairs: 坐标组，用 comma-wsp 分隔的多个坐标
- list-of-points: 点集，可以是 空 / 任意多空格 / 前后有任意多空格（含0）的坐标组

points 也可以直接转换为 path string，manim 中就是这样处理的，即把所有 wsp digit 都替换为 "L" wsp digit，然后把第一个 L 替换为 M

## <path\> 路径
<path\> 元素通过它的 `d` 属性来指定路径，值为一个字符串<br/>
这个路径字符串由一些控制命令和后面接着的参数构成，一共十种控制命令，分别有大写和小写的形式<br/>
大写表示后面的参数里的坐标是绝对位置，小写表示后面的参数里的坐标是相对于当前坐标的相对位置

并且为了压缩 SVG 的大小，也有一些允许的缩写规则：

- 可以省略不必要的 comma-wsp 分隔符
- 如果多次使用同一个命令，则除了第一次以外均可以省略命令
- 可以使用相对坐标
- 可以使用水平和垂直情况的 lineto
- 可以用 S/s/T/t 来省略第一个控制点

下面依次来说明这十种控制命令：

|命令|名称|参数|描述|
|:--:|:--:|:--|:--|
|M or m|moveto|(x y)+|开启一个新的路径，参数是起点坐标<br/>如果参数是多组坐标，则除第一个以外都当成 L/l 指令的参数来处理|
|Z or z|closepath||关闭路径，即从当前点到当前子路径开头点画一条直线<br/>Z 和 z 的效果相同|
|L or l|lineto|(x y)+|从当前点开始画直线，参数是端点坐标|
|H or h|horizontal lineto|x+|画一条水平线，到横坐标 x 的位置|
|V or v|vertical lineto|y+|画一条竖直线，到纵坐标 y 的位置|
|C or c|curveto|(x1 y1 x2 y2 x y)+|从当前点到 (x, y) 利用三阶贝塞尔画一条曲线<br/>其中 (x1, y1) 是当前点的控制点，(x2, y2) 是结束点的控制点|
|S or s|smooth curveto|(x1 y1 x y)+|从当前点到 (x, y) 利用三阶贝塞尔画一条曲线<br/>其中当前点的控制点是上一条三阶贝塞尔曲线的第二个控制点关于当前点的中心对称点，(x1, y1) 是结束点的控制点<br/>如果没有上一条路径或者上一条路径不是三阶贝塞尔曲线（CcSs），则当前点的控制点就是当前点|
|Q or q|quadratic<br/>bezier curveto|(x1 y1 x y)+|从当前点到 (x, y) 利用二阶贝塞尔画一条曲线<br/>其中 (x1, y1) 是控制点|
|T or t|smooth<br/>quadratic<br/>bezier curveto|(x y)+|从当前点到 (x, y) 利用二阶贝塞尔画一条曲线<br/>其中控制点是上一条二阶贝塞尔曲线控制点关于当前点的中心对称点<br/>如果没有上一条路径或者上一条路径不是二阶贝塞尔曲线（QqTt），则控制点就是当前点|
|A or a|elliptical arc|||

最后一个椭圆弧的参数和用法相对复杂，单独来说：

- 参数：(rx ry x-axis-rotation large-arc-flag sweep-flag x y)+
- 用法：
    - rx, ry：椭圆弧的水平和垂直半径
    - x-axis-rotation：一个角度，以 deg 为单位，表示 x 轴旋转角度
    - large-arc-flag: 0 或 1，是 0 表示这段椭圆弧应该是劣弧，1 表示这段椭圆弧应该是优弧
    - sweep-flag：0 或 1，是 0 表示从起点到终点沿逆时针画弧，1 表示从起点到终点顺时针画弧
    - x, y：终点坐标

??? example "A 命令例子"
    ![](/assets/images/cs/web/svg/arc.png)

### EBNF 语法
d 属性里的是 svg-path 类型，定义是：
```EBNF
svg-path:
    wsp* moveto-drawto-command-groups? wsp*
moveto-drawto-command-groups:
    moveto-drawto-command-group
    | moveto-drawto-command-group wsp* moveto-drawto-command-groups
moveto-drawto-command-group:
    moveto wsp* drawto-commands?
drawto-commands:
    drawto-command
    | drawto-command wsp* drawto-commands
drawto-command:
    closepath
    | lineto
    | horizontal-lineto
    | vertical-lineto
    | curveto
    | smooth-curveto
    | quadratic-bezier-curveto
    | smooth-quadratic-bezier-curveto
    | elliptical-arc
```

- drawto-command: 除了 M/m 以外的 9 种命令字符串
- drawto-commands: 用任意多（可为0） wsp 分隔的 drawto-command
- moveto-drawto-command-group: moveto 命令开头的命令组（用于指定一个子路径），可以仅有 moveto，也可以是由任意多（可省略）wsp 分隔的一些命令
- moveto-drawto-command-groups: 子路径集合，用任意多（可省略）wsp 分隔的 moveto-drawto-command-group
- svg-path: 可以为 空 / 开头结尾有任意多 wsp 的 moveto-drawto-command-groups

下面是各个命令的语法，都比较清晰，就不多解释了：
??? note "各个命令的语法"
    ```EBNF
    moveto:
        ( "M" | "m" ) wsp* moveto-argument-sequence
    moveto-argument-sequence:
        coordinate-pair
        | coordinate-pair comma-wsp? lineto-argument-sequence

    closepath:
        ("Z" | "z")

    lineto:
        ( "L" | "l" ) wsp* lineto-argument-sequence
    lineto-argument-sequence:
        coordinate-pair
        | coordinate-pair comma-wsp? lineto-argument-sequence

    horizontal-lineto:
        ( "H" | "h" ) wsp* horizontal-lineto-argument-sequence
    horizontal-lineto-argument-sequence:
        coordinate
        | coordinate comma-wsp? horizontal-lineto-argument-sequence

    vertical-lineto:
        ( "V" | "v" ) wsp* vertical-lineto-argument-sequence
    vertical-lineto-argument-sequence:
        coordinate
        | coordinate comma-wsp? vertical-lineto-argument-sequence

    curveto:
        ( "C" | "c" ) wsp* curveto-argument-sequence
    curveto-argument-sequence:
        curveto-argument
        | curveto-argument comma-wsp? curveto-argument-sequence
    curveto-argument:
        coordinate-pair comma-wsp? coordinate-pair comma-wsp? coordinate-pair

    smooth-curveto:
        ( "S" | "s" ) wsp* smooth-curveto-argument-sequence
    smooth-curveto-argument-sequence:
        smooth-curveto-argument
        | smooth-curveto-argument comma-wsp? smooth-curveto-argument-sequence
    smooth-curveto-argument:
        coordinate-pair comma-wsp? coordinate-pair

    quadratic-bezier-curveto:
        ( "Q" | "q" ) wsp* quadratic-bezier-curveto-argument-sequence
    quadratic-bezier-curveto-argument-sequence:
        quadratic-bezier-curveto-argument
        | quadratic-bezier-curveto-argument comma-wsp? 
            quadratic-bezier-curveto-argument-sequence
    quadratic-bezier-curveto-argument:
        coordinate-pair comma-wsp? coordinate-pair

    smooth-quadratic-bezier-curveto:
        ( "T" | "t" ) wsp* smooth-quadratic-bezier-curveto-argument-sequence
    smooth-quadratic-bezier-curveto-argument-sequence:
        coordinate-pair
        | coordinate-pair comma-wsp? smooth-quadratic-bezier-curveto-argument-sequence

    elliptical-arc:
        ( "A" | "a" ) wsp* elliptical-arc-argument-sequence
    elliptical-arc-argument-sequence:
        elliptical-arc-argument
        | elliptical-arc-argument comma-wsp? elliptical-arc-argument-sequence
    elliptical-arc-argument:
        nonnegative-number comma-wsp? nonnegative-number comma-wsp? 
            number comma-wsp flag comma-wsp? flag comma-wsp? coordinate-pair
    flag:
        "0" | "1"
    ```

### path string parser
??? note "python 写的 path string 解析"
    ```python
    class InvalidPathError(ValueError):
        pass


    class _PathStringParser:
        # modified from https://github.com/regebro/svg.path/
        def __init__(self, arguments, rules):
            self.args = []
            arguments = bytearray(arguments, "ascii")
            self._strip_array(arguments)
            while arguments:
                for rule in rules:
                    self._rule_to_function_map[rule](arguments)

        @property
        def _rule_to_function_map(self):
            return {
                "x": self._get_number,
                "y": self._get_number,
                "a": self._get_number,
                "u": self._get_unsigned_number,
                "f": self._get_flag,
            }

        def _strip_array(self, arg_array):
            # wsp: (0x9, 0x20, 0xA, 0xC, 0xD) with comma 0x2C
            # https://www.w3.org/TR/SVG/paths.html#PathDataBNF
            while arg_array and arg_array[0] in [0x9, 0x20, 0xA, 0xC, 0xD, 0x2C]:
                arg_array[0:1] = b""

        def _get_number(self, arg_array):
            pattern = re.compile(rb"^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
            res = pattern.search(arg_array)
            if not res:
                raise InvalidPathError(f"Expected a number, got '{arg_array}'")
            number = float(res.group())
            self.args.append(number)
            arg_array[res.start():res.end()] = b""
            self._strip_array(arg_array)
            return number

        def _get_unsigned_number(self, arg_array):
            number = self._get_number(arg_array)
            if number < 0:
                raise InvalidPathError(f"Expected an unsigned number, got '{number}'")
            return number

        def _get_flag(self, arg_array):
            flag = arg_array[0]
            if flag != 48 and flag != 49:
                raise InvalidPathError(f"Expected a flag (0/1), got '{chr(flag)}'")
            flag -= 48
            self.args.append(flag)
            arg_array[0:1] = b""
            self._strip_array(arg_array)
            return flag
    ```

## transform 的处理
transform 是对当前元素及其子元素的整个坐标系进行的变换，从左向右结合<br/>
所以也就可以看做对元素应用 transform，但是从右向左结合

所有的 transform 都可以看成一个 3 阶矩阵：

\begin{bmatrix}
a & c & e \\
b & d & f \\
0 & 0 & 1
\end{bmatrix}

作用方式是：

$$
\begin{bmatrix}
x_\text{prevCoordSys} \\
y_\text{prevCoordSys} \\
1
\end{bmatrix}
=
\begin{bmatrix}
a & c & e \\
b & d & f \\
0 & 0 & 1
\end{bmatrix}\cdot
\begin{bmatrix}
x_\text{newCoordSys} \\
y_\text{newCoordSys} \\
1
\end{bmatrix}
$$

其中 $(x_\text{prevCoordSys}, y_\text{prevCoordSys})$ 表示在 transform 前的坐标系统下的坐标，这个 3 阶 transform 的矩阵记为 [a b c d e f]

SVG 一共支持六种 transform，下面具体来说：

- matrix(a b c d e f): 施加矩阵 [a b c d e f] 作用
- translate(tx [ty]): 平移，x 轴移 tx，y 轴移 ty，如果没有 ty 就是 0。相当于矩阵 [1 0 0 1 tx ty]
- scale(sx [sy]): 缩放，x 轴缩放 sx 倍，y 轴缩放 sy 倍，如果没有 sy，则 sy 和 sx 相等。相当于矩阵 [sx 0 0 sy 0 0]
- rotate(angle [cx cy]): 顺时针旋转 angle 度，以 cx cy 为中心，没有指定就是原点
    - rotate(angle cx cy) 相当于 translate(cx cy) rotate(angle) translate(-cx -cy)
    - rotate(a) 相当于矩阵 [cos(a) sin(a) -sin(a) cos(a) 0 0]
- skewX(angle): x 轴倾斜 angle 度，相当于矩阵 [1 0 tan(a) 1 0 0]
- skewY(angle): y 轴倾斜 angle 度，相当于矩阵 [1 tan(a) 0 1 0 0]

### EBNF 语法
???+ note "transform 的 EBNF 语法"
    ```EBNF
    transform-list:
        wsp* transforms? wsp*
    transforms:
        transform
        | transform comma-wsp+ transforms
    transform:
        matrix
        | translate
        | scale
        | rotate
        | skewX
        | skewY
    matrix:
        "matrix" wsp* "(" wsp*
           number comma-wsp
           number comma-wsp
           number comma-wsp
           number comma-wsp
           number comma-wsp
           number wsp* ")"
    translate:
        "translate" wsp* "(" wsp* number ( comma-wsp number )? wsp* ")"
    scale:
        "scale" wsp* "(" wsp* number ( comma-wsp number )? wsp* ")"
    rotate:
        "rotate" wsp* "(" wsp* number ( comma-wsp number comma-wsp number )? wsp* ")"
    skewX:
        "skewX" wsp* "(" wsp* number wsp* ")"
    skewY:
        "skewY" wsp* "(" wsp* number wsp* ")"
    ```

正则匹配分离 transform:
```python
transform_pattern = re.compile("|".join([x + r"[^)]*\)" for x in transform_names]))
```
里面的 number 都可以用开头说到的正则来匹配

## 样式
默认样式：
```python
DEFAULT_STYLE = {
    "fill": "black",
    "stroke": "none",
    "fill-opacity": "1",
    "stroke-opacity": "1",
    "stroke-width": 0,
}
```
剩下的就是按照 css 的规则层叠就好了