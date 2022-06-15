---
counter: True
comment: True
---

# hexo 使用记录

!!! abstract 
    当时在用 mkdocs 搭建了博客之后感觉不像个博客的样子，所以换了 hexo，用来生成博客网站还是很方便的。

## 安装
hexo 基于 node.js，可以直接通过 `npm install -g hexo-cli` 来安装

## 使用
- 创建 blog 目录放置博客：
    ```shell 
    $ hexo init blog 
    # 也可以手动创建目录后进入
    $ mkdir blog & cd blog & hexo init 
    ```
- 安装需要的包：
    ```shell 
    $ npm install 
    ```
- 启动内置预览服务（默认端口 4000）：
    ```shell 
    $ hexo s  # hexo serve 
    ```
- 生成网站：
    ```shell 
    $ hexo g  # hexo generate
    ```
    之后会生成一个 `public/` 文件夹，为网站源码

hexo init 生成的目录结构为：
```text 
├── _config.yml   # 配置文件
├── package.json  # 应用信息
├── scaffolds/    # 模板文件夹
├── source/       # 源文件夹
|   └── _posts/   # 稿件文件夹
└── themes/       # 主题文件夹
```

创建一篇新的文章使用 `hexo new` 命令，默认会创建一篇 post，比如 `hexo new "test"` 会在 `source/_post/` 里使用 `scaffolds/post.md` 为模板创建一个 test.md 

## 配置
`_config.yml` 这个文件是 hexo 的配置文件，里面的内容：

- `title`：网站标题
- `subtitle`：副标题
- `description`：网站描述
- `keywords`：网站关键词
- `author`：作者
- `language`：语言
- `timezone`：时区

以上设置会出现在 meta 里

- `url`：网址
- `root`：网站根目录
- `permalink`：永久链接格式，比如 :year/:month/:day/:title/
- `source_dir`：源文件夹，默认 source
- `public_dir`：生成的网站文件夹
- `theme`：主题

……

所有配置还是看官网：https://hexo.io/zh-cn/docs/configuration

### 部署到 GitHub pages
配置文件中：
```yaml 
deploy:
- type: git
  repo: https://github.com/.../...
  branch: master
```
然后就可以通过 `#!shell hexo d`（`hexo deploy`）来部署到 GitHub pages 上（或者 `hexo d -g` 生成并部署）

## 一些插件
安装插件都可以通过 `npm install ... --save` 来安装

### hexo-abbrlink 
生成一个短的永久链接，安装后只需要在配置文件中改：
```yaml 
permalink: p/:abbrlink.html
abbrlink:
  alg: crc32
  rep: hex
```
就会为利用 crc32 为每篇文章设置一个 hex 值的永久链接

### hexo-blog-encrypt
可以为文章加密，只需要在 md 的文件头加上：
```yaml 
password: ...
```
就可以加密这篇文章。更多用法和设置在 GitHub 上：[:material-github: D0n9X1n/hexo-blog-encrypt](https://github.com/D0n9X1n/hexo-blog-encrypt)

### hexo-generator-index/archive/category/tag 
基本是必须要装的了，用来生成主页/归档/分类/标签文件夹
```yaml 
index_generator:
  path: ''
  per_page: 10
  order_by: '-date'

archive_generator:
  per_page: 30

tag_generator:
  per_page: 30

category_generator:
  per_page: 30
```
分别用来指定各个页面每个页面的文章个数

### hexo-generator-feed
用来生成 RSS 订阅 xml 文件
```yaml 
feed:
  enable: true
  type: atom
  path: atom.xml
  limit: 20
```

### hexo-generator-index-pin-top
置顶某篇文章，只需要在文件头加上 `top: true` 即可

但是 icarus 主题好像不支持……

### hexo-generator-search/searchdb
用来生成搜索相关
```yaml
search:
  path: search.xml
  field: all
  content: true
  limit: 9999
```

### hexo-wordcount
用来生成字数统计。好像不需要配置什么

## 主题
现在的博客用了一个挺简洁的主题，[:material-github: ppoffice/hexo-theme-icarus](https://github.com/ppoffice/hexo-theme-icarus)

但是这个主题的弊端也挺多，比如所有页面都会加载一个 content.json，里面存放了整个网站的所有文章包括内容，导致加载很慢（蠢的很）

整个主题基本上是用 jsx 来写的，样式是用 styl 写的，改的话还比较方便

比如增加置顶的功能：

???+ note "置顶"
    每篇文章的 card 和内容页面都是由 `layout/common/article.jsx` 来生成

    所以直接在 .card.level-left 里面加：
    ```html
    {page.top && <span class="level-item" style="color: #ff7242;">
    <i class="fas fa-thumbtack" style="margin-right: 0.3em;"></i>
    置顶</span>}
    ```
    就可以为文件头有 top: true 的文章在最顶部最左侧加上置顶标志

而且这个主题不支持从配置文件和当前目录嵌入 js 和 css，所以就直接去这个主题的 `source` 文件夹改就好了

## Reference
- [Hexo 官网](https://hexo.io)
- [zzq 浅谈用 Hexo+GitHub 搭建自己的 blog](https://afar5277.blog.luogu.org/post-zzq-hexoblog)
- [Hexo 博客搭建说明书（指北书）](https://www.luogu.org/blog/0Umaru0/hexo-bo-ke-da-jian-shuo-ming-shu-zhi-bei-shu-post)
- [从零搭建 Hexo + Github 博客](https://www.luogu.org/blog/Venus/build-hexo-github-blog)