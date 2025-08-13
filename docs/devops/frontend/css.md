---
counter: True
comment: True
---

# CSS

!!! abstract
    CSS 相关神奇妙妙用法记录。

    参考：

    - [MDN CSS docs](https://developer.mozilla.org/en-US/docs/Web/CSS/Nesting_selector)

## Selectors

- basic selectors
    - type: `#!css div { }` 选择全部 `#!html <div>` 元素
    - class: `#!css .class { }` 选择全部 `#!html <... class="class">` 元素
    - id: `#!css #id { }` 选择全部 `#!html <... id="id">` 元素
    - universal: `#!css * { }` 选择全部元素
- attribute selectors
    - `#!css div[title] { }` 选择具有 `title` 属性的全部 `#!html <div>` 元素
    - `#!css div[title="value"] { }` 选择具有 `title="value"` 属性的全部 `#!html <div>` 元素
    - `#!css div[title~="value"] { }` 选择具有 `title` 属性值包含 `value` 的全部 `#!html <div>` 元素
    - `#!css div[lang|="zh"] { }` 选择 `title="zh"` 或 `title="zh-CN"` 等 `#!html <div>` 元素
    - 根据 substring 匹配（不按空格分割）
        - `#!css [attr^=value] { }` 开头，`#!css [attr$=value] { }` 结尾，`#!css [attr*=value] { }` 中间包含 `value`
- selector lists
    - 逗号分隔，如 `#!css div, p { }` 选择全部 `#!html <div>` 和 `#!html <p>` 元素
    - 其中有一个非法则整条规则忽略
- combinators 组合用法
    - 空格分隔：`#!css div p { }` 选择所有 `#!html <div>` 元素下的 `#!html <p>` 元素（descendant）
    - \> 分隔：`#!css div > p { }` 选择所有 `#!html <div>` 元素下的直接子元素 `#!html <p>`（child）
    - \+ 分隔：`#!css div + p { }` 选择紧接在 `#!html <div>` 元素后的 `#!html <p>` 元素（next-sibling）
        - 反过来选择后面有紧接着的 `#!html <p>` 元素的 `#!html <div>` 元素：`#!css div:has(+ p) { }`
    - ~ 分隔：`#!css div ~ p { }` 选择所有在 `#!html <div>` 元素之后的 `#!html <p>` 元素（subsequent-sibling）
    - 不分隔：叠加选择所有条件，`#!css div.class#id[attr] { }` -> `#!html <div class="class" id="id" attr="value">`
- pseudo-classes 伪类
    - `#!css li:first-child { }` 选择每个作为第一个子元素的 `#!html <li>` 元素
        - 推荐使用 `#!css div *:first-child { }` 代替 `#!css div :first-child { }` 防止混淆
    - `#!css :hover { }` 悬停状态
- pseudo-elements 伪元素
    - `#!css p::first-line { }` 选择每个 `#!html <p>` 元素的第一行
    - `#!css p::before { content: "Note: "; }` 在每个 `#!html <p>` 元素前插入内容
    - `#!css p::after { content: " (end)"; }` 在每个 `#!html <p>` 元素后插入内容
    - `#!css ::selection` 选择被用户选中的内容
    - `#!css ::placeholder` 选择输入框中的 placeholder 内容
    - `#!css ::marker` 选择列表项的标记符号

### 嵌套选择器

```css
.parent {
    <parent styles>
    .child {
        <child styles>
    }
}
```

等价于

```css
.parent {
    <parent styles>
}
.parent .child {
    <child styles>
}
```

在子选择器中加入 `&` 表示父选择器插入的位置：

```css
.parent {
    <parent styles>
    &:hover {
        <parent hover styles>
    }
    .child & & {
        <styles>
    }
}
```

等价于

```css
.parent {
    <parent styles>
}
.parent:hover {
    <parent hover styles>
}
.child .parent .parent {
    <styles>
}
```

### 其他伪类

- `#!css :active` 激活状态（鼠标按下）
- `#!css :visited` 访问过的链接
- `#!css :first-child` 第一个子元素，`#!css :last-child` 最后一个子元素
- `#!css :nth-child(n)` 第 n 个子元素，`#!css :nth-last-child(n)` 倒数第 n 个子元素
    - n 可以是数字、`odd`（奇数）、`even`（偶数）、`an+b`（a 和 b 是整数，a>=0）
    - 例如 `#!css :nth-child(3n+1)` 表示第 1、4、7、10... 个子元素
    - `#!css :nth-last-of-type(n)` 和 `#!css :nth-of-type(n)` 类似
- `#!css :first-of-type` 第一个指定类型的子元素，`#!css :last-of-type` 最后一个指定类型的子元素
- `#!css :has(...)` 选择包含指定子元素的元素（... 是 relative selector，即 `#!css + p / > p` 等）
    - `#!css :has(a, b)` 表示 or，`#!css :has(a):has(b)` 表示 and
- `#!css :is(a, b)` a 或 b 任意一个，用于简写，可以生成一系列选择器
    - `#!css :is(a, b) :is(c, d)` 等价于 `#!css a c, a d, b c, b d`
- `#!css :where(...)` 类似 `#!css :is(...)`，但不会影响优先级
    ```css
    :is(section.is-style, footer.is-style) a { ... }
    :where(section.where-style, footer.where-style) a { ... }
    footer a { ... } /* 会覆盖 where 的规则，但不覆盖 is 的规则 */
    ```
- `#!css :not(...)` 选择不匹配指定 rule 的元素
- `#!css :root` 选择文档的根元素，通常是 `#!html <html>` 元素，常用于定义全局变量
    ```css
    :root {
        --main-color: red; /* 其他地方可以使用 var(--main-color) 来引用 */
    }
    ```

## 其他神奇用法

### 响应式设计

即根据设备的屏幕大小来调整样式。可以使用 @media 查询规则来实现：

```css
@media screen and (min-width: 960px) { /* 960px 宽及以上的屏幕应用下面的样式 */
  html {
    font-size: 137.5%;
  }
}
@media screen and (max-width: 600px) {
    ... /* 600px 宽及以下的屏幕应用下面的样式 */
}
```

### counter

通过 css 计数器可以实现标题的自动编号：

- counter-reset：创建并初始化一个计数器
- counter-increment：增加计数器的值
- counter()：获取计数器的当前值

```css
h1 {
  counter-reset: h2; /* 遇到 h1 时重置 h2 计数器 */
}
h2 {
  counter-reset: h3; /* 遇到 h2 时重置 h3 计数器 */
}
h2::before {
  counter-increment: h2; /* 遇到 h2 时增加 h2 计数器 */
  content: counter(h2);  /* 获取 h2 计数器的值并在标题前显示 */
  margin-right: 0.8rem;
}
h3::before {
  counter-increment: h3; /* 遇到 h3 时增加 h3 计数器 */
  content: counter(h2) "." counter(h3); /* 连接多个计数器 */
  margin-right: 0.8rem;
}
```

### 优先级与 important

```css
.selector.class {
    color: red;
}
.selector {
    color: blue;
}
```

即使 `.selector` 在后面定义，`.selector.class` 也会生效，因为它的限制更多优先级更高。

在通过自定义 css 覆盖原有样式时，需要注意这种情况，一般需要把 selector 写得和原有样式一样或更具体才会覆盖。或者在属性后面加上 `!important` 强制覆盖：

### 关于字体

一般 font-family 写法：

```css
font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans","Liberation Sans",sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol","Noto Color Emoji";
```

自定义 font-family 时注意 fallback 机制，最好把常见的字体都列出来，最后加上通用字体族（如 sans-serif、serif、monospace 等）。

自定义字体：

```css
@font-face {
    font-family: "Font Name";  /* 后续 font-family 中可以使用这个名字 */
    src: url("path/to/font.woff2") format("woff2"),
         url("path/to/font.woff") format("woff"); /* 可以提供多种格式以兼容不同浏览器 */
    font-weight: 400;    /* 支持的 weight */
    font-style: normal;  /* 支持的 style */
}
```

为了防止加载大型字体文件时卡住，可以将字体文件拆分为多个子集（subset），每个子集只包含部分字符，然后根据需要加载对应的子集：

```css
@font-face {
    font-family: "Font Name";
    src: url("path/to/font-subset1.woff2") format("woff2");
    unicode-range: ...;
}
@font-face {
    font-family: "Font Name";
    src: url("path/to/font-subset2.woff2") format("woff2");
    unicode-range: ...;
}
```

可以利用 [:material-github: KonghaYao/cn-font-split](https://github.com/KonghaYao/cn-font-split) 等工具来拆分字体文件。

<!-- ### flex 布局


### 关于居中 -->
