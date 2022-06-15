---
counter: True
comment: True
---

# mkdocs 使用记录

!!! abstract 
    我最早接触的网站生成器就是 mkdocs，然后用它搭了博客。但由于当时觉得看起来太平淡、功能少等原因抛弃了它换成了 hexo<br/>
    后来打算搞一个笔记本整理一些有价值的内容，所以搭了这个网站，用回了 mkdocs

    mkdocs 就很适合用来做这种站点，而且它基于 python，使用 pymarkdown 渲染 markdown 文档，最后使用 html 模板渲染，也很方便修改。所以 mkdocs 还是很香的

## 安装
mkdocs 是 python 的一个包，直接 `#!shell pip install mkdocs` 就可以了

## 使用
```shell
$ mkdocs new test    # 创建一个名为 test 的文件夹,存储代码
$ cd test
```
此时的目录结构
```test
test/
 ├── docs/            # 存放markdown文档
 │     └── index.md   # 主页
 └── mkdocs.yml       # 配置文件
```
打开实时渲染服务（默认端口 8000），并且使用 watchdog 监控文件夹内的更改
```shell
$ mkdocs serve
```
在浏览器中输入 `127.0.0.1:8000` 预览，终端键入 ++ctrl+c++ 关闭服务器
```shell
$ mkdocs build         # 生成静态网页代码
```
这时已经生成了`site/`文件夹，可以将里面的内容部署到网站上了
```shell 
$ mkdocs gh-deploy 
```
自动根据 `mkdocs.yml` 中设置的项目地址部署到 GitHub 的 gh-pages 分支中

## 配置文件
- `site_name`：**必填**，文档主标题名称
- `site_url`：最终的网站 url
- `repo_url`：对应的 GitHub repo 的链接，用于 deploy 和右上角的链接
- `edit_url`：相对于 repo 链接的 docs 目录地址
- `site_description` 站点描述
- `copyright`：左下角版权信息
- `theme: `  主题样式例如:
    ```yaml
    theme: 
      name: 'material'     # 使用material主题,需要pip安   装mkdocs-material
      language: 'zh'       # 使用中文
      icon:
        logo: ...          # 左上角的 logo 
      custom_dir: ...      # 用于覆盖模板
      feature: 
        ...
      font:                # 字体
        text: ...
        code: ...
      palette:
        ... # 配色方案
    ```
- `markdown_extensions`：需要添加的 pymarkdown 扩展（包已经随 mkdocs 默认安装），具体各种扩展的用法看[官方文档](https://python-markdown.github.io/extensions/)
- `extra`：主题需要的其他配置，比如 material 主题的右下角链接 `social` 和流量分析 `analytics` 的设置
- `extra_css`：附加的 css 文件，可以是 url 也可以是相对于 docs 的相对路径
- `extra_javascript`：附加的 js 文件，可以是 url 也可以是相对于 docs 的相对路径。会放到 body 的最后，如果需要放到 head 里需要用覆盖模板的方式
- `plugins`：一些插件，比如搜索 `search`，显示最近修改时间 `git-revision-date-localized`
- `nav`：目录结构

本站的配置文档在：https://github.com/TonyCrane/note/blob/master/mkdocs.yml，可供参考

具体的各种用法还是看官方文档比较好，很全面

## Reference
- [mkdocs 官方文档](https://www.mkdocs.org/)
- [pymarkdown 内置 extensions](https://python-markdown.github.io/extensions/)
- [pymdown-extensions 文档](https://facelessuser.github.io/pymdown-extensions/)
- [mateial for mkdocs 文档](https://squidfunk.github.io/mkdocs-material/)
- [shafish.cn 上的教程](https://shafish.cn/blog/mkdocs/)