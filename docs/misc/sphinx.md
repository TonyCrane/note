---
counter: True
comment: True
---

# Sphinx 使用记录

!!! abstract 
    对于项目文档，mkdocs 看起来也很舒适，但是貌似不能直接根据文档字符串来生成文档。而同样基于 python 的 sphinx 就很好用，对于 python 项目，用 sphinx 来生成文档还是很方便的

## 安装
使用 `#!shell pip install Sphinx` 通过 pip 安装即可 

## 使用
文档：https://www.sphinx-doc.org/en/master/usage/quickstart.html

它和 mkdocs/hexo 的差别还是很大的，比如配置文件是 python 文件而不是 yml，页面源码默认用 rst（reStructuredText）而不是 markdown，并且生成文档是使用 make html 命令来通过 Makefile 文件编译出文档

## 生成文档 
如果项目已经使用 rst 语法编写好了文档字符串，则可以直接提取出来生成文档

前提是需要在 `conf.py` 中配置好 path 

```ReST 
.. autoclass:: A.B.C 
    :members:
```
就会自动导入 A.B.C 这个类，并为自身和它所有的带有文档字符串的方法生成文档。
```ReST
.. automodule: A
    :members:
```
会自动为 A 这个模块生成文档

文档：https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html

## 插件
Sphinx 还可以自定义插件。文档：https://www.sphinx-doc.org/en/master/extdev/index.html#dev-extensions