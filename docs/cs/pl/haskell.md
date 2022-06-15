---
counter: True
comment: True
---

> Haskell 是一种标准化的，通用的纯函数式编程语言，有惰性求值和强静态类型。它的命名源自美国逻辑学家哈斯凯尔·加里，他在数理逻辑方面上的工作使得函数式编程语言有了广泛的基础。在 Haskell 中，“函数是第一类对象”。作为一门函数编程语言，主要控制结构是函数。Haskell 语言是1990年在编程语言 Miranda 的基础上标准化的，并且以λ演算为基础发展而来。这也是为什么 Haskell 语言以希腊字母 “λ”（Lambda）作为自己的标志。Haskell 具有“证明即程序、命题为类型”的特征。
> <div style="text-align: right">———— 维基百科</div>

## 基础运算
- `+ - * / ()`：加减乘除
- `div`：整除
- `mod`：取模
- `True False`：布尔值
- `|| && not`：或且非
- `==`：条件判断，相等
- `/=`：条件判断，不等

### 函数调用
Haskell 中调用函数不加括号，先写出函数名，然后逐个列出参数，用空格隔开：
```haskell
ghci> max 1 2
2
```
前缀（prefix）函数与中缀（infix）函数转换：

- 对前缀函数加<code>``</code>使其变成中缀函数
- 对中缀函数加`()`使其变成前缀函数

```haskell
ghci> 4 `div` 2
2
ghci> 1 `max` 2
2
ghci> (+) 1 2
3
ghci> (||) True False
True
```

---

## List
列表是 Haskell 中很常见的数据类型，和 Python 中不同，Haskell 中的列表中的所有元素必须是同一个类型。

以下是列表常用的函数：

- `(++)` :: [a] -> [a] -> [a]：合并两个列表
- `(:)` :: a -> [a] -> [a]：将单个元素并入列表。[1, 2, 3] 是 1:2:3:[] 的语法糖
- `(!!)` :: [a] -> Int -> a：通过索引取出某个位置上的元素。a !! 1 相当于 Python 中的 a[1]
- `head` :: [a] -> a：返回列表的第一个元素
- `tail` :: [a] -> [a]：返回列表中除去第一个元素后的列表（若只有一个元素则返回空列表[]）
- `last` :: [a] -> a：返回列表中的最后一个元素
- `init` :: [a] -> [a]：返回列表中除去最后一个元素后的列表
- `length` :: Foldable t => t a -> Int：返回列表的长度
- `null` :: Foldable t => t a -> Bool：返回列表是否为空
- `reverse` :: [a] -> [a]：返回翻转后的列表
- `take` :: Int -> [a] -> [a]：返回列表a的前n个元素的列表(take n a)
- `drop` :: Int -> [a] -> [a]：返回列表a中除去前n个元素后的列表(drop n a)
- `maximum` :: (Foldable t, Ord a) => t a -> a：返回列表中的最大值
- `minimum` :: (Foldable t, Ord a) => t a -> a：返回列表中的最小值
- `sum` :: (Foldable t, Num a) => t a -> a：返回列表中所有元素的和
- `product` :: (Foldable t, Num a) => t a -> a：返回列表中所有元素的积
- `elem` :: (Foldable t, Eq a) => t a -> Bool：判断值n是否在列表a中
    ```haskell
    elem n a
    -- 或
    n `elem` a --用``包上可以变成中缀函数使用
    ```

### Texas ranges
使用`..`可以表示出范围并自动推导：
```haskell
ghci> [1 .. 10]  
[1,2,3,4,5,6,7,8,9,10]  
ghci> ['a' .. 'z']  
"abcdefghijklmnopqrstuvwxyz"  
ghci> ['K' .. 'Z']  
"KLMNOPQRSTUVWXYZ" 
ghci> [2, 4 .. 20]  
[2,4,6,8,10,12,14,16,18,20]  
ghci> [3, 6 .. 20]  
[3,6,9,12,15,18]
ghci> [5, 4 .. 1]
[5,4,3,2,1]
```
也可以用来生成无穷列表，如 [1..]、[1, 3..]。同时也有函数可以生成无穷列表：

- `cycle` :: [a] -> [a]：将原列表不断循环生成无穷列表
- `repeat` :: a -> [a]：将传入的值不断重复生成无穷列表
    - `replicate` :: Int -> a -> [a]：将值a重复n次，返回生成的列表(replicate n a)

### List comprehension
Haskell 中也有列表推导，形式是一个中括号，左侧为表达式，右侧为变量的范围和约束条件
```haskell
ghci> [x * 2 | x <- [1 .. 10]]  
[2,4,6,8,10,12,14,16,18,20]  
ghci> [x * 2 | x <- [1 .. 10], x * 2 >= 12]  
[12,14,16,18,20]
ghci> [ x | x <- [50 .. 100], x `mod` 7 == 3]  
[52,59,66,73,80,87,94]   
ghci> [x * y | x <- [2, 5, 10], y <- [8, 10, 11]]  
[16,20,22,40,50,55,80,100,110]
```

---

## Tuple
Haskell中的元组可以有不同长度，元素可以有不同类型。并且一个元组的类型由其中所有元素的类型共同决定。它的常用函数：

- `fst` :: (a, b) -> a：返回含有两个元素元组中的第一个元素
- `snd` :: (a, b) -> b：返回含有两个元素元组中的第二个元素
- `zip` :: [a] -> [b] -> [(a, b)]：接收两个列表，返回一个列表，每个元素是依次将两个列表中元素配对成的二元组

---

## Syntax in Functions
函数可以直接定义：
```haskell
plus x y = x + y
```
这时Haskell会自动推断函数的类型为(Num a) => a -> a -> a。但是最好在定义函数前声明函数的类型：
```haskell
plus :: (Num a) => a -> a -> a
plus x y = x + y
```

### Pattern matching
定义函数时可以使用模式匹配语法。运行时依次将输入与给出的模式相匹配，如果匹配，就执行对应操作；不匹配，就继续与下一个模式相匹配，直到匹配成功，也因此，最后必须要给出一种通用的匹配来接收与给出模式全不匹配的输入。如：
```haskell
factorial :: (Integral a) => a -> a  
factorial 0 = 1  
factorial n = n * factorial (n - 1)  
```
```haskell
first :: (a, b, c) -> a  
first (x, _, _) = x  
  
second :: (a, b, c) -> b  
second (_, y, _) = y  
  
third :: (a, b, c) -> c  
third (_, _, z) = z  
```
其中 `_` 表示任何值，且不关心它的内容，只是用来占位

列表的 (:) 操作也可以用来进行模式匹配：
```haskell
head' :: [a] -> a  
head' [] = error "Can't call head on an empty list, dummy!"  
head' (x:_) = x

sum' :: (Num a) => [a] -> a  
sum' [] = 0  
sum' (x:xs) = x + sum' xs  
```
但 (++) 操作不可以用来模式匹配

在针对列表进行模式匹配时，如果同时需要整个列表、列表的第一个值、列表除第一个值外的内容，可以使用 `xs@(q:qs)`。比如 [1, 2, 3] 通过 `xs@(q:qs)` 匹配后，xs 为 [1, 2, 3]，q 为 1，qs 为 [2, 3]

### Guard syntax
在函数的定义中，也可以使用守卫（guard）语法：
```haskell
max' :: (Ord a) => a -> a -> a  
max' a b   
    | a > b     = a  
    | otherwise = b 
```
先给出传入的参数变量，然后下一行缩进后加 |，| 后面等号前表示进行的判断，如果为 True 则返回这个等号后面的值；如果为 False 则继续判断下一行，直到 otherwise

### Case expressions
在函数的定义中，也可以使用 case 表达式来配合模式匹配使用：
```haskell
case expression of pattern -> result  
                   pattern -> result
                   ...  
```
例如：
```haskell
head' :: [a] -> a  
head' [] = error "No head for empty lists!"  
head' (x:_) = x  
-- 等价于：
head' :: [a] -> a  
head' xs = case xs of [] -> error "No head for empty lists!"  
                      (x:_) -> x  
```
```haskell
describeList :: [a] -> String  
describeList xs = "The list is " ++ case xs of [] -> "empty."  
                                               [x] -> "a singleton list."   
                                               xs -> "a longer list."  
-- 等价于：
describeList :: [a] -> String  
describeList xs = "The list is " ++ what xs  
    where what [] = "empty."  
          what [x] = "a singleton list."  
          what xs = "a longer list." 
```

### where
声明在函数定义中要使用的局部变量，可以使用 where 关键字：
```haskell
initials :: String -> String -> String  
initials firstname lastname = [f] ++ ". " ++ [l] ++ "."  
    where (f:_) = firstname  
          (l:_) = lastname  
```
在 where 中，也可以使用上面的模式匹配

### let
`let <bindings> in <expression>` 语法可以在函数的定义中使用，也可以在普通算式或列表中使用：
```haskell
cylinder :: (RealFloat a) => a -> a -> a  
cylinder r h = 
    let sideArea = 2 * pi * r * h  
        topArea = pi * r ^2  
    in  sideArea + 2 * topArea  
```
```haskell
ghci> 4 * (let a = 9 in a + 1) + 2  
42 
ghci> [let square x = x * x in (square 5, square 3, square 2)]  
[(25,9,4)] 
```

### if statement
Haskell 中的 if 语句为：
```haskell
if ... then ...
else ...
-- or if ... then ... else ...
-- or
if ... then ...
else if ... then ...
else ...
```
其中最后一个 else 无论如何也不可以省去

---

## Higher Order Functions
### Currying
Haskell 中的函数是柯里化（Currying）的，可以看作所有函数都只接收一个参数，而接收两个参数的函数实际上是这个函数接收了第一个参数后返回了一个接收第二个参数的函数，然后用这个函数接收第二个参数，返回最终的结果。比如 max 函数，它的类型签名是：
<p style="text-align: center;">max :: Ord a => a -> a -> a</p>

可以看成 a -> (a -> a)，即接收一个参数，返回一个类型为 a -> a 的函数。比如 max 1 的类型签名是：
<p style="text-align: center;">max 1 :: (Ord a, Num a) => a -> a</p>

因此 max 1 2，也就等同于 (max 1) 2，即将函数 max 1 应用在数字2上

同时，函数也可以接收函数作为参数，参数有函数的函数就被称为高阶函数（Higher Order Functions）

### 一些高阶函数
#### zipWith
<p style="text-align: center;">zipWith :: (a -> b -> c) -> [a] -> [b] -> [c]</p>

第一个参数为一个函数，然后接收两个列表，将其对应元素传入接收的函数中，得到的结果组成一个新的列表。如果两个传入的列表长度不同，以最短的列表为准，长列表中超出的元素省略。用例：
```haskell
ghci> zipWith (+) [4,2,5,6] [2,6,2,3]  
[6,8,7,9]  
ghci> zipWith max [6,3,2,1] [7,3,1,5]  
[7,3,2,5]  
```

#### flip
<p style="text-align: center;">flip :: (a -> b -> c) -> b -> a -> c</p>

flip 函数接收一个二元函数，返回一个新的二元函数，将其输入的两个参数顺序反过来：
```haskell
ghci> zip [1,2,3,4,5] "hello"
[(1,'h'),(2,'e'),(3,'l'),(4,'l'),(5,'o')]
ghci> flip zip [1,2,3,4,5] "hello"  
[('h',1),('e',2),('l',3),('l',4),('o',5)]
```

#### map
<p style="text-align: center;">map :: (a -> b) -> [a] -> [b]</p>

map 函数接收一个函数 f 和一个列表 a，将函数 f 应用在列表 a 的每个元素中，并返回得到的所有结果组成的列表 b：
```haskell
ghci> map (+3) [1,5,3,1,6]  
[4,8,6,4,9]  
```

#### filter
<p style="text-align: center;">filter :: (a -> Bool) -> [a] -> [a]</p>

filter 函数接收一个函数 f 和一个列表 a，将列表 a 中的每个元素传入函数 f 中，如果结果为 True 就保留，结果为 False 就抛弃，返回所有保留的元素组成的新列表：
```haskell
ghci> filter even [1..10]  
[2,4,6,8,10] 
```

#### takeWhile
<p style="text-align: center;">takeWhile :: (a -> Bool) -> [a] -> [a]</p>

takeWhile 函数接收一个函数 f 和一个列表 a，将列表 a 中从左向右每个元素传入函数 f，直到结果为 False 停止，返回停止前传入的所有元素组成的新列表：
```haskell
ghci> takeWhile (/=' ') "word1 word2"
"word1"
```

### Function application
函数应用可以使用 `$`，`$` 是一个函数，它的类型是：
<p style="text-align: center;">($) :: (a -> b) -> a -> b</p>

它可以改变函数结合优先级，将左侧函数应用于全部右侧内容上，相当于给右侧整体加上了括号。否则函数默认左结合，会依次向右应用而不会应用在整体上。
```haskell
f $ g x
-- 等价于
f (g x)
-----
f g x
-- 等价于
(f g) x
```
### Function Composition
函数复合可以使用 `.`，`.` 也是一个函数，它的类型是：
<p style="text-align: center;">(.) :: (b -> c) -> (a -> b) -> a -> c</p>

定义是：
<p style="text-align: center;">f . g = \x -> f (g x)</p>

但是函数复合的优先级要比函数执行低，比如：
```haskell
sum . replicate 5 . max 6.7 8.9
```
会先执行 max 6.7 8.9 并返回 8.9，然后将 sum、replicate 5、8.9 复合，但两个函数无法和一个值 (8.9) 复合，所以会抛出异常。因此要使用 `$`来规定先复合再执行：
```haskell
sum . replicate 5 . max 6.7 $ 8.9
```

### lambda

Haskell 语言中的 lambda 表达式是用 `\` 来表示的（因为看着像$\mathtt{\lambda}$？）<br/>
具体语法是
```haskell
\para1 para2 ... -> return
```
"->" 前的 para1 para2 ... 是传入参数，单个多个都可以，需要用空格隔开；"->" 后的 return 是计算得到的返回值。一般需要用括号将整个表达式括起来，防止返回值部分一直向右延伸。

### fold和scan
fold 和 scan 都接收三个参数（一个二元函数，一个初始值 accumulator，一个要折叠的列表），fold 返回一个值，而 scan 返回一个列表<br/>
传入的二元函数 `f :: a -> b -> b` 将 accumulator 和从列表中取出的值一同传入（l 则 accumulator 在左边为第一个参数，r 则 accumulator 在右边为第二个参数）

#### foldl
左折叠，每次从列表最左侧取出一个值，和 accumulator 一起传入二元函数，并且 accumulator 在左边为第一个参数，如：
```haskell
foldl f a xs
```
它的结果计算过程为
```haskell
> foldl f a [x1, x2, x3]
[1.] a = f a x1
[2.] a = f a x2 = f (f a x1) x2
[3.] a = f a x3 = f (f (f a x1) x2) x3
```
可以看出 f (f a x1) x2 其实就是 foldl f a [x1, x2]
而且因此，foldl 在计算时最外层需要找到 x3，这样如果 xs 是一个无穷列表，那么将无法计算，陷入无穷。所以 foldl 虽然看起来从左边取值，但是函数需要从右侧展开，并不适用于无穷列表

#### foldr
右折叠，每次从列表最右侧取出一个值，和 accumulator 一起传入二元函数，并且 accumulator 在右边为第二个参数，如：
```haskell
foldr f a xs
```
它的结果计算过程为
```haskell
> foldr f a [x1, x2, x3]
[1.] a = f x3 a
[2.] a = f x2 a = f x2 (f x3 a)
[3.] a = f x1 a = f x1 (f x2 (f x3 a))
```
从中可以看出 f x2 (f x3 a) 就是 foldr f a [x2, x3]
因此可以使用递归来写一个和 foldr 效果一样的函数:
```haskell
foldr' :: (a -> b -> b) -> b -> [a] -> b
foldr' _ x [] = x
foldr' f a (x:xs) = f x (foldr' f a xs)
```
也可以看出，最外层计算时只需要 x1 并且向下递归，并不会接触到列表末尾，因此可以用于无穷列表。foldr 即使看上去从右边取值，但是要从左开始展开，可以用于无穷列表

例如：
```haskell
ghci> foldr (||) False (repeat True)
True    -- 由于逻辑运算存在短路，计算值全应为True，所以直接返回了
ghci> foldl (||) False (repeat True)
-- 这里什么都不会发生，直到电脑内存被爆掉
-- 因为函数刚开始就需要列表最右侧的值，所以在不断计算这个无穷列表
```

#### scanl 和 scanr
scan 类似 fold，只是将中间得到的每一个值都添加进一个列表中并返回这个列表
scanl 则向右延伸这个列表，scanr 则向左延伸这个列表
但是它和 fold 恰恰相反，scanl 能用于无穷列表，而 scanr 不能
```haskell
> scanr f a [x1, x2, x3]
[1.] 最右侧元素(-1 in python) : a
[2.] 右侧第二个元素(-2) : f x3 a
[3.] 右侧第三个元素(-3) : f x2 (f x3 a)
[4.] 右侧第四个元素(-4) : f x1 (f x2 (f x3 a))
```
可以看出 f x2 (f x3 a) 是 foldr f a [x2, x3]，也是 scanr f a [x2, x3] 的第一个元素
因此可以用递归来写一个和 scanr 效果一样的函数：
```haskell
scanr' :: (a -> b -> b) -> b -> [a] -> [b]
scanr' _ x [] = [x]
-- scanr' f a (x:xs) = f x (foldr f a xs) : scanr' f a xs
scanr' f a (x:xs) = f x q : qs
                    where qs@(q:_) = scanr' f a xs
```
scanl 也是同理：
```haskell
scanl' :: (b -> a -> b) -> b -> [a] -> [b]
scanl' _ x [] = [x]
scanl' f a (x:xs) = a : scanl' f (f a x) xs
```

也可以看出，scanr 返回的列表的第一个元素是最后添加进去的，所以它无法用于无穷列表。而 scanl 返回的列表中的元素是从左到右依次添加，可以用于无穷列表截取前一部分结果：
```haskell
ghci> take 10 (scanl (+) 0 [1..])
[0,1,3,6,10,15,21,28,36,45]
ghci> take 10 (scanr (+) 0 [1..])
[*** Exception: stack overflow
```

#### 使用 foldr 编写 foldl
pdcxs 还给我介绍了一个神奇的操作，用 foldl 来定义 foldr：
```haskell
foldl' f z xs = foldr (\x g y -> g (f y x)) id xs z
```

它利用 foldr (\x g y -> g (f y x)) id xs 生成一个函数，作用于z得到结果。

先来看一下 foldr 的类型：
```haskell
foldr :: Foldable t => (a -> b -> b) -> b -> t a -> b
-- 可以看成 (a -> b -> b) -> b -> [a] -> b
```
但是在这个例子中，类型 b 并不是一个数字，而是一个函数 (b -> b)。

所以这里 foldr 的类型可以写成：
<p style="text-align: center;">(a -> (b -> b) -> (b -> b)) -> (b -> b) -> [a] -> (b -> b)</p>

对应于用法 foldr (\x g y -> g (f y x)) id xs ，它返回的值应该是一个函数，类型为 b -> b（后面要作用于z）
而 xs 对应于 [a]；id 对应于 (b -> b)
所以 (\x g y -> g (f y x)) 要对应于：
<p style="text-align: center;">(a -> (b -> b) -> (b -> b))</p>

因此可以推断出 x 的类型是 a；y 的类型是 b；而返回的值为一个类型为 (b -> b) 的函数。

再看，返回的值是 g (f y x) ，其中 f y x 返回的是一个值，类型为 b
所以 g 接收一个类型 b，返回一个类型 b -> b。即 g 的类型为：
<p style="text-align: center;">b -> (b -> b)</p>

现在根据 foldr 的定义：
<p style="text-align: center;">foldr f a (x:xs) = f x (foldr f a xs)</p>

带入计算一下：
> xs 即为 [x1..xn]，为了方便，用 xs' 来表示 [x2..xn]，用 xs'' 来表示 [x3..xn]
>
> 定义中的 f 即为 (\x g y -> g (f y x))，a 即为 id

```haskell
  foldr (\x g y -> g (f y x)) id xs z
= (\x g y -> g (f y x)) x1 (foldr (...) id xs') z
```
写完第一步，可以发现，x1 (foldr (...) id xs') z 正好分别对应了 lambda 表达式中的 x、g、y。可以将其应用，进一步展开：
```haskell
  (\x g y -> g (f y x)) x1 (foldr (...) id xs') z
= (foldr (...) id xs') (f z x1)
```
不难发现，原式 (foldr (...) id xs) z 等价于：
<p style="text-align: center;">(foldr (...) id xs') (f z x1)</p>

跟着这个思路，xs 每次少一个开头的元素 x'，z 每次变换成为 f z x'
因此下一步：
```haskell
  (\x g y -> g (f y x)) x1 (foldr (...) id xs') z
= (foldr (...) id xs') (f z x1)
= (foldr (...) id xs'') (f (f z x1) x2)
= (foldr (...) id xs''') (f (f (f z x1) x2) x3)
= ...
```
可以发现，已经有了规律。那么最终停止时是什么样呢？

最后到了不能在展开时，最前面的 foldr (...) id xs 已经变成了 foldr (...) id []
而根据前面 foldr 的定义 foldr _ x [] = x ，它应该返回 id

所以最后的结果：
(id 的定义：id x = x)
```haskell
  ...
= (foldr (...) id xs') (f z x1)
= (foldr (...) id xs'') (f (f z x1) x2)
= ...
= (foldr (...) id []) (f (.. (f z x1) ..) xn)
= id (f (.. (f z x1) ..) xn)
= f (.. (f z x1) ..) xn
```
那么最后这个结果就很熟悉了，它就是 foldl f z xs。
所以我们推导出了这个用 foldr 表示 foldl 的写法是正确的。

---

## Modules
Haskell 会自动加载 Prelude 模块（module），如果在 GHCi 中再加载其他模块，需要使用 `:m + ...`，比如加载 Data.List 模块：
<p style="text-align: center;">Prelude> :m + Data.List</p>

而在 hs 文件中引入模块，需要使用 `import` 语句，下面和 python 的对比可以便于理解：
```haskell
import Data.List
-- from Data.List import *

import Data.List (nub, sort)
-- from Data.List import nub, sort

import Data.List hiding (nub)
-- 从Data.List中引入所有，但不引入nub函数

import qualified Data.List
-- import Data.List

import qualified Data.List as Li
-- import Data.List as Li
```

### 编写 Modules
模块中要包含将要使用的一些函数，像正常的 hs 文件一样写即可，但头部需要有导出语句（export）。比如一个模块文件名叫 `ModuleA.hs`，那它的头部需要写：
```haskell
module ModuleA
( functionA
, functionB
, functionC
) where

```
而且文件中的所有函数只导出需要使用的即可。比如该文件中还含有 functionD 供前三个函数内部使用，那么在 import ModuleA 之后也无法调用 functionD。

---

## Types & Typeclasses

### Types
Haskell 有一个静态类型系统，任何变量、函数都会具有类型，并且有类型判断功能，没给出的类型会自动识别。<br/>
Type 的首字母全为大写，常用的有：

- `Int`：整型，有上下界范围，-2147483647～2147483648
- `Integer`：整数，无界，但是效率比Int低
- `Float`：单精度浮点型
- `Double`：双精度浮点型
- `Bool`：布尔值
- `Char`：字符
- `String`：字符串，等同于`[Char]`
- `Ordering`：大小关系，包含LT、EQ、GT，且它们有大小关系 LT < EQ < GT

列表的类型是由其中元素决定的，并且列表中元素必须是同一类型，所以列表的类型就是其元素类型外加`[]`。

元组的类型由其中各个元素的类型共同决定，因为元组中的元素可以是不同类型。如 ("abc", 'a', True) 的类型是 ([Char], Char, Bool)。

### Typeclasses
类型类（Typeclass）是定义一系列功能的接口，如果一个 Type 属于一个 Typeclass 的成员，那么它可以实现这个类型类所规定的功能。一个 Type 也可以属于多个Typeclass<br/>
Typeclass的首字母也全为大写，常见的有：

- `Eq`：可判断是否相等
- `Ord`：可比较大小
- `Show`：可展示成字符串
- `Read`：可从字符串转换成特定类型
- `Enum`：可枚举（连续），即可以使用 pred 和 succ 函数得到前驱和后缀
- `Bounded`: 有上下界，如果元组中所有元素都属于 Bounded，那这个元组的类型也属于 Bounded
- `Integral`：是整数，包括 Int 和 Integer
- `RealFloat`： 是实浮点数，包括 Float 和 Double
- `RealFrac`：是实分数，包括 Float、Double 和 Ratio（在 Data.Ratio 模块中）
- `Floating`：是浮点数，包括 Float、Double 和 Complex（在 Data.Complex 模块中）
- `Real`：是实数，包括 Integral 和 RealFrac 的成员
- `Fractional`：是分数，包括 RealFrac 和 Floating 的成员
- `Num`：是数字，包括上述所有数字相关的类型


### Type variables
如果查看一个函数的类型，比如 `head`，那么将会返回以下类型：
<p style="text-align: center;">head :: [a] -> a</p>

其中的 a 就是一个类型变量（type variable），它在 head 中可以属于任何类型，在这里只是表示返回值的类型和输入的列表中的元素的类型相一致。

在函数的类型表达式其实可以看作 $\lambda$ 表达式，它适用于 $\alpha$ 变换（$\alpha$-conversion）。即 a 在这里可以指 Int、Char 等类型，也可以指 [Char], (Int, Char), 甚至函数 Int -> Int 等。

在大部分函数的类型中，类型变量需要保证是某个 Typeclass 的成员才能完成操作。比如 `(==)` 函数，它需要传入的参数是可判断相等的，即是 Eq 的成员，那么 `(==)` 的类型就是：
<p style="text-align: center;">(==) :: (Eq a) => a -> a -> Bool</p>

其中 `=>` 前的部分 (Eq a) 就是类约束（class constraint），它规定了 a 是 Eq 的成员，所以 `(==)` 函数传入的两个参数都是 a 类型，且都是 Eq 的成员，保证了它们之间是可以比较是否相等的。

### 定义新 Type
定义一个新的 Type 需要使用 `data` 关键字，比如定义 `Bool` 需要使用：
<p style="text-align: center;">data Bool = False | True</p>

其中 = 左侧的部分定义了新类型的名称 `Bool`，右侧的部分叫做值构造器（value constructors），表示了 Bool 类型的值为 False 或 True。<br/>
并且名称和值构造器的首字母都需要大写。

另外，值构造器也是函数，它们可以有参数，叫做项（field）。比如：
```haskell
data Shape = Circle Float Float Float | Rectangle Float Float Float Float   
```
它定义了一个新 Type 叫 Shape，值构造器是 Circle 和 Rectangle，Circle 接收三个参数都是 Float 类型，Rectangle 接收四个 Float 类型参数。<br/>
如果查看 Circle 的类型，将返回：
<p style="text-align: center;">Circle :: Float -> Float -> Float -> Shape</p>

如果想要让它能给直接显示出来，需要让它属于 Show 类型类。在代码中只需要在结尾加上 `deriving (Show)`:
```haskell
data Shape = Circle Float Float Float | Rectangle Float Float Float Float deriving (Show)
```

类型的名称和值构造器名称也可以相同，比如：
```haskell
data Point = Point Float Float deriving (Show)
```

#### 导出 Type
在文件中定义了新的 Type 之后，如果在别的文件中将其作为模块导入，则需要先导出。比如文件 `Shapes.hs` 中定义了 Shape 和 Point，以及其他的一些函数，那么文件开头需要写：
```haskell
module Shapes
( Shape(..)
, Point(..)
, functionA
, functionB
) where
```
其中的 `Shape(..)` 导出了 Shape 类型和它所有的值构造器，`..` 代表了它的所有值构造器。因此，`Shape(..)` 相当于 `Shape (Circle, Rectangle)`。

如果不想要导出值构造器，即不允许使用值构造器的方法来创建 Shape 类型的变量。那么需要将 `Shape(..)` 替换为 `Shape`，这样就只导出了 Shape 类型，而不导出其值构造器。

#### Record Syntax
如果想要方便地取出类型实例中的参数，可以使用 Record 语法，如：
```haskell
data Point = Point { xcoord :: Float
                   , ycoord :: Float
                   } deriving (Show)
```
在值构造器的参数部分先加一个大括号，然后指定取出值的函数名称（xcoord, ycoord），后面指定类型（:: Float）。这样 xcoord 和 ycoord 就都是一个类型为 Point -> Float 的函数，可以通过下面方法来访问值：
```haskell
ghci> let point = Point 1.0 2.0
ghci> xcoord point
1.0
ghci> ycoord point
2.0
```
同时也可以通过下面方法来创建这个 point：
```haskell
point = Point {ycoord=2.0, xcoord=1.0}
```

#### Type parameters
值构造器可以接收参数，类型也可以接收参数，这样它就成为了类型构造器（type constructors）。如 Maybe 的定义：
<p style="text-align: center;">data Maybe a = Nothing | Just a</p>

它的值是 Nothing 时，类型为 Maybe a，是多态的（polymorphic）。<br/>
它的值不是 Nothing 时，类型取决于值 Just a 中 a 的类型，可以构造出 Maybe Int、Maybe [Char] 等多种类型：
```haskell
Nothing :: Maybe a
Just 1 :: Num a => Maybe a
Just 'a' :: Maybe Char
Just "abc" :: Maybe [Char]
```

可以用这种方法改写 Point：
```haskell
data Point x y = Point { xcoord :: x
                       , ycoord :: y
                       } deriving (Show)
```

但使用类型参数（type parameters）并不是总是方便，比如在声明函数类型的时候不能只使用 Point 来表示 Point 类型，而是必须写成 Point Float Float。

而且不能在定义类型构造器时添加类约束（class constraint），不然在之后声明函数类型的时候也都需要添加类约束，如：
```haskell
data (Ord k) => Map k v = ... 
toList :: (Ord k) => Map k a -> [(k, a)]
```

#### Either
Either 是一个类型构造器，它有两个值构造器，定义是：
```haskell
data Either a b = Left a | Right b deriving (Eq, Ord, Read, Show)  
```
如果使用了 Left，那它的 a 的类型就是具体的；如果使用了 Right，那它的 b 的类型就是具体的：
```haskell
ghci> Right 20  
Right 20  
ghci> Left "w00t"  
Left "w00t"  
ghci> :t Right 'a'  
Right 'a' :: Either a Char  
ghci> :t Left True  
Left True :: Either Bool b  
```
Either 可以看作 Maybe 的补充，比如 Maybe 在使用时，出现异常可以返回 Nothing，但只是一个 Nothing，不包含任何信息；但 Either 包含左值和右值，正常结果返回右值，而出现异常就可以返回包含错误信息的左值，比如安全除法：
```haskell
safeDiv :: Int -> Int -> Maybe Int
safeDiv _ 0 = Nothing
safeDiv x y = Just (x `div` y)

ghci> safeDiv 4 2
Just 2
ghci> safeDiv 1 0
Nothing
```
而使用 Either：
```haskell
safeDiv :: Int -> Int -> Either String Int
safeDiv _ 0 = Left "Divided by zero"
safeDiv x y = Right (x `div` y)

ghci> safeDiv 4 2
Right 2
ghci> safeDiv 1 0
Left "Divided by zero"
```

#### Derived instances
想要使一个定义的类满足某些 Typeclass 的需求，需要从其派生（derive），比如：
```haskell
data Day = Monday | Tuesday | Wednesday | Thursday | Friday | Saturday | Sunday   
           deriving (Eq, Ord, Show, Read, Bounded, Enum)  
```
这样 Day 类型的值（Monday～Sunday）之间就可以比较是否相等（从 Eq 派生），比较大小（从 Ord 派生，左侧为小，右侧为大），显示成字符串（从 Show 派生），从字符串中读取（从 Read 派生），包含边界（从 Bounded 派生），可以枚举（从 Enum 派生，按照值构造器中的顺序依次向右）

#### Type synonyms
为了阅读方便，书写简便，可以使用 `type` 关键字为已有类型创建别名（synonyms）。比如 String 的定义：
<p style="text-align: center;">type String = [Char]</p>

在所有需要使用字符串（即 [Char]）的地方都可以使用 String 来代替，它们是完全一致的，只是 String 更简便易读。<br/>
同时，类型别名也可以接收类型参数

#### newtype keyword
除了 `data`、`type` 关键字之外，还可以用 `newtype` 关键字来定义一个新的类型，比如 `Control.Applicative` 模块中的 ZipList：
```haskell
newtype ZipList a = { getZipList :: [a] }
```
- 不同于 type，它不是别名，可以使用 record 语法来直接定义取出值的函数
- 不同于 data，它只能有一个值构造器，但是速度要比 data 快，而且更加懒惰

#### Recursive data structures
一个类型也可以递归定义，比如一颗二叉树：
```haskell
data Tree a = EmptyTree | Node a (Tree a) (Tree a) deriving (Show, Read, Eq)  
```

### 定义新 Typeclass
定义一个新的 Typeclass 需要使用 class 关键字，例如定义 Eq 类型类：
```haskell
class Eq a where  
    (==) :: a -> a -> Bool  
    (/=) :: a -> a -> Bool  
    x == y = not (x /= y)  
    x /= y = not (x == y)  
```
其中 `a` 是一个类型变量，前两行声明了需要实现的函数的名字及其类型，后两行表明了需要的函数之间可以相互定义（不必要）。

包含了后两行之后，只定义 (==) 函数或者 (/=) 函数都可以完成全部定义，它们（`(==) | (/=)`）成为这个类型类的最小完整定义（minimal complete definition）

查看一个类型类的成员需要实现的函数可以在 GHCi 中使用 `:info`：
<p style="text-align: center;">ghci> :info Eq</p>

#### 手动创建实例
使一个类型成为一个类型类的实例可以直接使用 `deriving` 来自动完成，也可以通过使用 instance 关键字来手动完成。比如使 Point 成为 Show 的实例：
```haskell
instance Show Point where
    show (Point x y) = "(" ++ show x ++ ", " ++ show y ++ ")"

-- in ghci
ghci> Point 1.0 2.0
(1.0, 2.0)
```
这样就可以自定义显示的内容，否则使用 deriving 的话只会直接将其转化为字符串。

同时也要注意类型和类型构造器的区别，传入给 instance 的第二个参数应该为类型而不是类型构造器，比如 Maybe：
```haskell
instance Eq Maybe where  
    ...    
-- 错误用法，因为Maybe是类型构造器而不是类型

instance Eq (Maybe m) where  
    ...
-- 错误用法，因为m不一定是Eq的成员

instance (Eq m) => Eq (Maybe m) where  
    Just x == Just y = x == y  
    Nothing == Nothing = True  
    _ == _ = False  
```

#### Functor Typeclass
Functor 也是一种类型类，它只规定了一个函数：
```haskell
class Functor f where
    fmap :: (a -> b) -> f a -> f b
```
其中 `f` 是一个类型构造器，而不是一个具体类型

### Kinds
一个值的类型叫做类型（Type），而一个类型的类型叫做 Kind。可以通过 GHCi 中 `:k` 来查看 Kind：
```haskell
ghci> :k Int
Int :: *
ghci> :k Maybe
Maybe :: * -> *
ghci> :k Maybe Int
Maybe Int :: *
ghci> :k Either
Either :: * -> * -> *
```
其中的星号 `*` 代表了一个具体类型（concrete type）。Int 本身就是一个具体类型，所以 Int 的 Kind 是 \*。而 Maybe 是一个类型构造器，它接收一个具体类型返回一个新的具体类型，所以 Maybe 的 Kind 是 \* -> \*。如果给 Maybe 传入了一个 Int，那么得到的 Maybe Int 就是一个具体的类型，它的 Kind 就是 \*。Either 也是一个类型构造器，但它接收两个类型才产生一个新的类型，所以 Either 的 Kind 是 \* -> \* -> \*。

---

## Input/Output

### 运行 Haskell 程序
不在 GHCi 中运行一个 Haskell 程序有两种方式：

1. 编译运行：
    ```sh
    $ ghc --make code
    $ ./code
    ```
2. 通过 `runhaskell` 命令直接运行：
    ```sh
    $ runhaskell code.hs
    ```

### 输出文本
在一个 Haskell 程序中输出文字需要定义一个 main 函数：
```haskell
main = putStrLn "Hello World"
```
其中 putStrLn 的类型是：
<p style="text-align: center;">putStrLn :: String -> IO ()</p>

putStrLn 接收一个 String 类型，并返回一个结果为 () 类型的 IO 动作（I/O action）。所以 main 函数的类型为 IO ()。（IO 的 Kind 是\* -> \*）

除此之外，还有其他默认提供的输出文本的函数：

- `putStr`：输出文本，结尾不换行
- `putChar`：输出单个字符，结尾不换行。接收的参数为单个 Char，不是 String（用单引号不是双引号）
- `print`：可以接收任何 Show 的成员，先用 show 转化为字符串然后输出。等同于 putStrLn . show

#### do block
在 main 函数中使用多个 putStrLn 需要使用 do 语句：
```haskell
main = do
    putStrLn "Line1"
    putStrLn "Line2"
```
其中最后一行一定要返回 IO () 类型的值

### 输入文本
输入文字需要在 do 块中使用 getLine：
```haskell
main = do
    line <- getLine
    putStrLn line
```
getLine 的类型是：
<p style="text-align: center;">getLine :: IO String</p>

而 <- 操作符将 getLine 中的 String 提取了出来给到了 line，使 line 变成了 String 类型的一个字符串

而且使用输入的字符串必须要经过一次 <-，不能直接使用 getLine 作为字符串，因为 getLine 不是 String 类型，而是 IO String 类型

除此之外，还可以使用 getChar 来获取单个字符，但仍然需要使用 <- 操作符来提取 Char

### 其他 IO 相关函数用法
#### return
Haskell 中的 return 和其他命令式语言中的 return 完全不同，它不会使函数直接结束并返回一个值。

main 函数必须定义为类型为 IO () 的函数，所以在 main 函数中使用 if 语句，如果不输出的话也不可以直接放下什么都不干，因为这时候 main 函数的类型不是 IO ()。所以这时需要使用 return () 来为 main 函数指定为 IO () 类型，例如：
```haskell
main = do 
    line <- getLine
    if null line
        then return () -- <-这里
        else do
            ...
```
使用 <- 操作符也可以直接将 return 语句中的内容提取出来，比如 a <- return 'A'，执行后 a 就是 'A'。

#### when
when 包含在 `Control.Monad` 模块中，它表示在满足第一个参数的条件下会执行第二个函数，否则会 return ()。比如：
```haskell
import Control.Monad   
  
main = do  
    c <- getChar  
    when (c /= ' ') $ do  
        putChar c  
        main  
```
等同于：
```haskell
main = do     
    c <- getChar  
    if c /= ' '  
        then do  
            putChar c  
            main  
        else return () 
```

#### sequence
sequence 在 IO 中使用时可以达成 [IO a] -> IO [a] 的效果，所以可以用作：
```haskell
[a, b, c] <- sequence [getLine, getLine, getLine]
```

#### mapM & mapM_
在 IO 相关的地方使用 map，可以使用 mapM 和 mapM_，其中 mapM 有返回值而 mapM_ 直接扔掉了返回值：
```haskell
ghci> mapM print [1,2,3]  
1  
2  
3  
[(),(),()]  
ghci> mapM_ print [1,2,3]  
1  
2  
3  
```

#### forever
forever 函数包含在 `Control.Monad` 模块中。在 main 函数开头加上 forever 函数可以使后面的 do 块一直重复执行直到程序被迫终止，如：
```haskell
import Control.Monad
  
main = forever $ do
    ...
```

#### forM
forM 函数包含在 `Control.Monad` 模块中，它的功能和 mapM 类似，从第一个参数中逐个取出元素传入第二个参数（一个接收一个参数的函数）中，并且第二个参数可以返回 IO a 类型。比如：
```haskell
import Control.Monad

main = do 
    colors <- forM [1, 2, 3, 4] (\a -> do
        putStrLn $ "Which color do you associate with the number " ++ show a ++ "?"  
        color <- getLine  
        return color)
    putStrLn "The colors that you associate with 1, 2, 3 and 4 are: "  
    mapM putStrLn colors
```

#### getContents
getLine 获取一整行，而 getContents 从标准输入中获取全部内容直到遇到 EOF，并且它是 lazy 的，在执行了 foo <- getContents 后，它并不会读取标准输入并且赋值到 foo，而是等到需要使用 foo 的时候再从标准输入读取。

getContents 在使用管道传入文字时很常用，可以代替 forever+getLine 使用，比如一个 Haskell 程序文件 code.hs：
```haskell
import Data.Char  
  
main = do  
    contents <- getContents  
    putStr (map toUpper contents)  
```
使用 ghc --make code 编译后，通过管道传入文字：
```sh
cat text.txt | ./code
```
会将 text.txt 中的所有字母转为大写并输出

#### interact
上述功能还可以转化为一个 String -> String 的函数：
```haskell
upperStrings = unlines . map (map toUpper) . lines
```
而在 main 中使用这个函数就需要：
```haskell
main = do
    contents <- getContents
    putStr (upperStrings contents)
```
但是 String -> String 类型的函数在输入输出中的使用太常见了，所以可以使用 interact 函数来简化。interact 的类型是：
<p style="text-align: center;">interact :: (String -> String) -> IO ()</p>

可以看出它接收一个 String -> String 的函数，并返回一个 IO () 类型，所以可以直接用在 main 上。

于是整个转换为大写的程序就可以简化为：
```haskell
main = interact $ unlines . map (map toUpper) . lines
```

### 文件和流
以下与文件和流相关的函数都包含在 `System.IO` 模块中

#### openFile
openFile 函数可以用来打开一个文件，它的类型是：
<p style="text-align: center;">openFile :: FilePath -> IOMode -> IO Handle</p>

其中 `FilePath` 是 String 的 type synonyms，用一个字符串来表示需要打开的文件的路径

`IOMode`的定义是：
```haskell
data IOMode = ReadMode | WriteMode | AppendMode | ReadWriteMode
```
所以它一共只有四个值，用来表示进行 IO 操作的模式

openFile 返回一个 IO Handle 类型的值，将其用 <- 操作符提取后会出现一个 Handle 的值。但不能从 Handle 中直接使用文字，还需要使用一系列函数：

- `hGetContents` :: Handle -> IO String ，从 Handle 中读取全部内容，返回一个 IO String
- `hGetChar` :: Handle -> IO Char ，从 Handle 中读取一个字符
- `hGetLine` :: Handle -> IO String ，从 Handle 中读取一行，返回一个 IO String
- `hPutStr` :: Handle -> String -> IO () ，向 Handle 中输出字符串
- `hPutStrLn` :: Handle -> String -> IO () ，同上

在使用 openFile 进行文件操作后，需要使用 hClose 手动关闭 Handle。hClose :: Handle -> IO ()，接收一个 Handle 并返回 IO ()，可以直接放在 main 函数末尾

所以使用 openFile 读取一个文件中的全部内容并输出的全部代码是：
```haskell
import System.IO

main = do
    handle <- openFile "text.txt" ReadMode
    contents <- hGetContents handle
    putStrLn contents
    hClose handle
```

#### withFile
withFile 类似 Python 中的 with open，它在读取文件使用之后不需要手动 close 文件。它的类型是：
<p style="text-align: center;">withFile :: FilePath -> IOMode -> (Handle -> IO a) -> IO a</p>

可以看出，它接收三个参数：

- `FilePath`：一个表示文件路径的String
- `IOMode`：打开文件的模式
- `(Handle -> IO a)`：一个函数，表示对读取文件后的Handle索要进行的操作，需要返回一个I/O action；而这个返回值也将作为withFile的返回值

现在使用 withFile 来改写上述代码：
```haskell
import System.IO

main = withFile "text.txt" ReadMode (\handle -> do
    contents <- hGetContents handle
    putStrLn contents)
```

withFile 的功能相当于以下函数：
```haskell
withFile' :: FilePath -> IOMode -> (Handle -> IO a) -> IO a  
withFile' path mode f = do  
    handle <- openFile path mode   
    result <- f handle  
    hClose handle  
    return result  
```

#### readFile
readFile 可以更加简化读取文件内容的操作，它的类型：
<p style="text-align: center;">readFile :: FilePath -> IO String</p>

它只需要输入一个表示文件路径的字符串，返回其中以其中内容为内容的 I/O action：
```haskell
import System.IO

main = do
    contents <- readFile "text.txt"
    putStrLn contents
```

#### writeFile
writeFile 简化了写入文件的操作，它的类型：
<p style="text-align: center;">writeFile :: FilePath -> String -> IO ()</p>

传入的第一个参数是要写入的文件的路径，第二个参数是要写入的字符串，返回一个IO ()

#### appendFile
appendFile 类似 writeFile，但使用它不会覆盖文件中原来内容，而是直接把字符串添加到文件末尾

#### buffer
文件以流的形式被读取，默认文字文件的缓冲区（buffer）大小是一行，即每次读取一行内容；默认二进制文件的缓冲区大小是以块为单位，如果没有指定则根据系统默认来选择。

也可以通过 `hSetBuffering` 函数来手动设置缓冲区大小，这个函数的类型：
<p style="text-align: center;">hSetBuffering :: Handle -> BufferMode -> IO ()</p>

它接收一个 handle，和一个 BufferMode，并返回 IO ()。其中 BufferMode 有以下几种：

- `NoBuffering`：没有缓冲区，一次读入一个字符
- `LineBuffering`：缓冲区大小是一行，即每次读入一行内容
- `BlockBuffering (Maybe Int)`：缓冲区大小是一块，块的大小由 Maybe Int 指定：
    - `BlockBuffering (Nothing)`：使用系统默认的块大小
    - `BlockBuffering (Just 2048)`：一块的大小是 2048 字节，即每次读入 2048 bytes 的内容

缓冲区的刷新是自动的，也可以通过 `hFlush` 来手动刷新
<p style="text-align: center;">hFlush :: Handle -> IO ()</p>

传入一个 handle，返回 IO ()，即刷新对应 handle 的缓冲区

#### openTempFile
openTempFile 可以新建一个临时文件：
<p style="text-align: center;">openTempFile :: FilePath -> String -> IO (FilePath, Handle)</p>

`FilePath` 指临时文件要创建的位置路径，`String` 指临时文件名字的前缀，返回一个 I/O action，其内容第一个 `FilePath` 是创建得到的临时文件的路径，`Handle` 是临时文件的 handle

例如：
```haskell
import System.IO

main = do
    (tempFile, tempHandle) <- openTempFile "." "temp"
    ...
    hClose tempHandle
```
`"."` 指临时文件要在当前目录创建，`"temp"` 指临时文件名字以 temp 开头。最终得到的 tempFile 就是 ./temp.......，temp 后为随机数字，如`./temp43620-0`

### 路径操作
相关函数都包含在 `System.Directory` 模块中，全部内容见 [System.Directory](https://hackage.haskell.org/package/directory-1.3.6.2/docs/System-Directory.html)

#### getCurrentDirectory
<p style="text-align: center;">getCurrentDirectory :: IO FilePath</p>

直接返回一个 I/O action，其内容是一个字符串表示当前路径的绝对路径

#### removeFile
<p style="text-align: center;">removeFile :: FilePath -> IO ()</p>

输入一个文件路径，并删除掉它

#### renameFile
<p style="text-align: center;">renameFile :: FilePath -> FilePath -> IO ()</p>

输入一个原路径，一个新路径，为原路径的文件重命名为新路径的名

#### doesFileExist
<p style="text-align: center;">doesFileExist :: FilePath -> IO Bool</p>

检查文件是否存在，返回一个包含布尔值的 I/O action

### Command line arguments
`System.Environment` 模块中提供了两个函数可以用来处理传入命令行的参数

#### getArgs
<p style="text-align: center;">getArgs :: IO [String]</p>

不需要输入参数，直接返回一个 I/O action，内容为传入命令行的参数（一个由String组成的列表）。相当于 C 语言中的 argv[1:]

#### getProgName
<p style="text-align: center;">getProgName :: IO String</p>

返回 I/O action，内容为程序的名字，相当于 C 语言中的 argv[0]

### Randomness
和随机数有关的函数都包含在 `System.Random` 模块中。GHCi 启动时可能不会包含 System.Random 的配置，导致无法找到模块。需要通过 stack 打开:
```sh
stack ghci --package random
```

Haskell 要求同样的程序需要运行出同样的结果，除了用到了 I/O action，所有会造成不同结果的函数都要交给 I/O action 来完成

那要使随机数脱离 IO 存在，就要用到随机生成器（random generator）

`System.Random` 模块提供了几个生成随机数的函数：

#### random
<p style="text-align: center;">random :: (Random a, RandomGen g) => g -> (a, g)</p>

其中又有两个新的 typeclass，Random 表示可以取随机，RandomGen 表示随机数生成器。random 函数接收一个随机数生成器，返回一个元组，其中第一个元素是生成的随机数，第二个元素是一个新的随机数生成器

获取随机数生成器可以使用 `mkStdGen` 函数：
<p style="text-align: center;">mkStdGen :: Int -> StdGen</p>

其中 `StdGen` 是一个 RandomGen 的实例

运用 random 生成随机数需要指定类型，不然程序无法确定 `a` 是什么类型。例如：
```haskell
ghci> random (mkStdGen 100) :: (Int, StdGen)
(9216477508314497915,StdGen {unStdGen = SMGen 712633246999323047 2532601429470541125})
ghci> random (mkStdGen 100) :: (Char, StdGen)
('\537310',StdGen {unStdGen = SMGen 712633246999323047 2532601429470541125})
ghci> random (mkStdGen 100) :: (Bool, StdGen)
(True,StdGen {unStdGen = SMGen 712633246999323047 2532601429470541125})
```
再次运行同样的函数，会得到同样的结果。所以如果需要生成其他的随机数，需要更换生成器，就可以使用上一次调用结果返回的新随机数生成器：
```haskell
threeCoins :: StdGen -> (Bool, Bool, Bool)  
threeCoins gen =   
    let (firstCoin, newGen) = random gen  
        (secondCoin, newGen') = random newGen  
        (thirdCoin, newGen'') = random newGen'  
    in  (firstCoin, secondCoin, thirdCoin) 
```

#### randoms
<p style="text-align: center;">randoms :: (Random a, RandomGen g) => g -> [a]</p>

randoms 接收一个 RandomGen，返回一个随机的无穷列表。因为它是无穷的，所以不会返回新的随机数生成器

#### randomR
<p style="text-align: center;">randomR :: (Random a, RandomGen g) => (a, a) -> g -> (a, g)</p>

可以用来生成有范围的随机数，第一个参数是一个元组，表示生成随机数的范围(闭区间)

#### randomRs
<p style="text-align: center;">randomRs :: (Random a, RandomGen g) => (a, a) -> g -> [a]</p>

同上两个，生成有范围的无穷随机数列表

#### getStdGen
如果想要让程序每次运行得到不同的随机结果，需要使用 `getStdGen` 来获取全局随机数生成器，它会在每次运行的时候产生不同的值，也因此，它返回的是一个 I/O action，而不是一个直接的 StdGen
<p style="text-align: center;">getStdGen :: Control.Monad.IO.Class.MonadIO m => m StdGen</p>

即可以看成 getStdGen :: IO StdGen，需要使用 <- 操作符将 StdGen 提取出来

但是在同一个程序中，getStdGen 的结果是相同的，全局随机数生成器不会自动更新，所以就需要另一个函数 newStdGen

#### newStdGen
<p style="text-align: center;">newStdGen :: Control.Monad.IO.Class.MonadIO m => m StdGen</p>

执行 newStdGen 会进行两个操作：

- 更新全局随机数生成器，下次执行 getStdGen 会获得不同的结果
- 返回一个 I/O action，包含一个新的 StdGen（但是这个生成器和全局生成器也不同）

### Exceptions
程序在运行失败时会抛出异常，可以通过 `Control.Exception` 模块中的 `catch` 函数来捕获异常：
<p style="text-align: center;">catch :: Exception e => IO a -> (e -> IO a) -> IO a</p>

第一个参数是要进行的操作，以 IO a 为返回值的类型，第二个参数是一个函数，它接收异常并进行操作，例如：
```haskell
import Control.Exception

main = main' `catch` handler

main' :: IO ()
main' = do
    ...

handler :: Exception e => e -> IO ()
handler e =  putStrLn "..."
```

也可以利用守卫（guard）语法和 `System.IO.Error` 中的函数来判断 IO 异常的类型来进行不同操作：
```haskell
import System.Environment
import System.IO.Error
import Control.Exception
  
main = toTry `catch` handler
              
toTry :: IO ()  
toTry = do (fileName:_) <- getArgs  
           contents <- readFile fileName  
           putStrLn $ "The file has " ++ show (length (lines contents)) ++ " lines!"  
  
handler :: IOError -> IO ()  
handler e  
    | isDoesNotExistError e = putStrLn "The file doesn't exist!"  
    | otherwise = ioError e  
```

具体相关全部函数见文档：[System.IO.Error](https://hackage.haskell.org/package/base-4.15.0.0/docs/System-IO-Error.html)、[Control.Exception](https://hackage.haskell.org/package/base-4.15.0.0/docs/Control-Exception-Base.html)

---

## Functors
函子（Functor）是一个类型类（typeclass），和其他类型类一样，它规定了其实例类必须实现的功能（例如 Eq 类型类规定了它的实例必须是可以比较是否相等的），Functor 规定类它的实例必须是可以进行映射的。Functor 要求使用 `fmap` :: (a -> b) -> f a -> f b 函数来实现这个功能，它接收一个 a -> b 类型的函数、一个内部元素为 a 类型的函子，返回一个内部元素为 b 类型的函子

Functor 可以比作盒子，那 fmap 函数就相当于给定一个函数和一个盒子，将盒子中的全部元素都应用这个函数，再返回应用函数后的盒子

函子的实例必须是一个 Kind 为 \* -> \* 的类型构造器，因为它要求其是一个盒子，盒子在接收内容后才会成为一个具体的类型。fmap 中的 `f a` 和 `f b` 也是因为 `f` 是一个类型构造器，在接收类型 a/b 后才会变成一个具体类型（f a 和 f b）出现在函数类型声明中

Functor 的定义是:
```haskell
class Functor f where
    fmap :: (a -> b) -> f a -> f b
    (<$) :: a -> f a -> f b
    (<$) = fmap . const
```
可以发现 Functor 不仅需要 fmap 函数，还需要一个 <$ 函数，它接收一个 a 类型的变量和一个内容为 b 类型的函子，返回一个内容为 a 类型的函子；作用就是将传入的函子中的所有元素都替换为传入的第一个参数，比如：
```Haskell
ghci> 'a' <$ [1, 2, 3]
"aaa"
```
但它不是声明一个函子实例必须的，因为它可以使用 fmap 和 const 函数复合来实现，其中 const 的类型签名：
<p style="text-align: center;">const :: a -> b -> a</p>

即接收两个参数，但始终只返回第一个参数

### Functor 实例
#### []
列表 [] 是一个函子，它通过 map 函数来实现 fmap 的功能：
```haskell
instance Functor [] where
    fmap = map
```
<p style="text-align: center;">map :: (a -> b) -> [a] -> [b]</p>

map 和 fmap 要求的相同，达成的目的也一致。map 接收一个函数和一个列表，它会将列表中的所有元素都应用这个函数后再返回这个列表

#### Maybe
Maybe 也具有 kind \* -> \*，它也是一个函子：
```haskell
instance Functor Maybe where
    fmap f Nothing = Nothing
    fmap f (Just x) = Just (f x)

ghci> fmap (*2) Nothing
Nothing
ghci> fmap (*2) (Just 2)
Just 4
```

#### Either a
Either 的 kind 是\* -> \* -> \*，显然它不是函子，但是固定了一个传入类型的 Either a 的 kind 是\* -> \*，也是一个函子：
```haskell
instance Functor (Either a) where
    fmap f (Left x) = Left x
    fmap f (Right x) = Right (f x)

ghci> fmap (*2) (Left 4)
Left 4
ghci> fmap (*2) (Right 4)
Right 8
```
因为使用 Either 时一般用右值表示正常结果，左值表示异常信息，所以使用 fmap 时只对右值进行操作，如果时左值则保持不变（而且左值此时也作为确定类型确定值存在）

#### IO
IO 也是一个函子，使用 fmap 对 IO 中内容应用函数：
```haskell
instance Functor IO where
    fmap f action = do
        result <- action
        return (f result)

ghci> fmap ("input: "++) getLine
test
"input: test"
```

#### (,) a
(,) 表示一个二元组的类型构造器，(,) :: \* -> \* -> \*，而确定了第一个元素的类型后就变成了 (,) a，它的 kind 是 \* -> \*。也是一个函子，进行 fmap 函数时只对第二个元素应用：
```haskell
instance Functor ((,) a) where
    fmap f (x, y) = (x, f y)
```
只剩一个元素的三元组和四元组也都是函子，fmap 也只对最后一个元素应用：
```haskell
instance Functor ((,,) a b) where
    fmap f (a, b, c) = (a, b, f c)

instance Functor ((,,,) a b c) where
    fmap f (a, b, c, d) = (a, b, c, f d)
```

#### (->) r
-> 也是一个类型构造器，它的 kind：
<p style="text-align: center;">(->) :: * -> * -> *</p>

一个映射（一元函数）的类型 a -> b 也可以写成 (->) a b，它是由类型 a 和类型 b 输入到类型构造器 -> 中后形成的一个具体类型。所以确定了输入类型后的一元函数的类型就是 (->) r（其中 `r` 是输入的类型）

规定的 fmap 的类型签名是：
<p style="text-align: center;">fmap :: (a -> b) -> f a -> f b</p>

其中的 f 是函子，而在这个实例中 (->) r 就是函子，将其带入 f 可以得到：
<p style="text-align: center;">fmap :: (a -> b) -> ((-> r) a) -> ((-> r) b)</p>

把其中的 (->) 换成中缀可以得到：
<p style="text-align: center;">fmap :: (a -> b) -> (r -> a) -> (r -> b)</p>

传入两个函数，一个类型为 a -> b，一个类型为 r -> a，返回一个函数，类型为 r -> b。<br/>
不难推测这个 fmap 是将这两个函数复合了，先对输入对 r 应用第二个函数产生类型 a 的结果，然后在应用第一个函数产生类型 b 的结果，所以 (->) r 定义的 fmap 是：
```haskell
instance Functor ((->) r) where
    fmap f g = (\x -> f (g x))
```
所以 (->) r 的 fmap 其实就是函数复合 (.)：
```haskell
instance Functor ((->) r) where
    fmap = (.)
```
```haskell
ghci> :t fmap (*3) (+100)  
fmap (*3) (+100) :: (Num a) => a -> a  
ghci> fmap (*3) (+100) 1  
303  
ghci> (*3) `fmap` (+100) $ 1  
303  
ghci> (*3) . (+100) $ 1  
303
```

### Functor Laws
所有的函子都应该满足两个定律。这两个定律不是 Haskell 强制要求的，但应该确保一个函子满足这两个定律：

1. `fmap id = id`（其中 id 为函数 `(\x -> x)`）：即对一个函子 fmap id，那它应该返回本身（fmap id a = id a = a，a 为一个函子），比如：
    ```haskell
    ghci> fmap id [1, 2, 3]
    [1,2,3]
    ghci> fmap id (Just 2)
    Just 2
    ```
2. `fmap (f . g) = fmap f . fmap g`：即函子的 fmap 支持结合律
    fmap (f . g) a = fmap f . fmap g $ a = fmap f (fmap g a)，其中`a`为一个函子
    fmap (f . g) (Just x) = fmap f (fmap g (Just x)) = fmap f (Just (g x)) = Just (f (g x))
    ```haskell
    ghci> fmap ((*3) . (+100)) (Just 1)
    Just 303
    ```

满足第一个定律的函子一定满足第二个定律，所以只要检查函子是否满足第一个定律即可

### Intuition
对于函子和 fmap，有两种理解方法

1. 函子是一种容器（container）；fmap 接收一个函数和一个容器，在容器内部应用这个函数，返回应用后的新容器
2. 函子是一种计算上下文（context）；fmap 是柯里化的，把其类型签名看作
<p style="text-align: center;">fmap :: (a -> b) -> (f a -> f b)</p>
&emsp;&emsp;接收一个函数返回另一个函数，传入函数 g :: a -> b，fmap 将其转换为新的函数
<p style="text-align: center;">fmap g :: f a -> f b</p>
&emsp;&emsp;使普通的函数 g 可以在计算上下文 f 中使用，这种转换也被称为提升（lift）

### 常用函数
#### <$>
`<$>` 函数是 `fmap` 的中缀形式（它看着类似 `$`，`f $ 3` 将 f 应用在单个值 3 上，而 `f <$> [1, 2, 3]` 将 f 应用在一个函子上，也就是应用在一个函子内部的所有值上）：
```haskell
ghci> fmap (*2) (Just 2)
4
ghci> (*2) <$> Just 2
4
```

#### $>
`$>` 函数包含在 `Data.Functor` 模块中
<p style="text-align: center;">($>) :: Functor f => f a -> b -> f b</p> 

Functor 定义时要求了 `<$` 函数，将函子内部的元素全部替换为指定的某个值，而 `$>` 正好将 `<$` 函数的两个参数反了过来，相当于 `flip (<$)`：
```haskell
ghci> 'a' <$ [1, 2, 3]
"aaa"
ghci> [1, 2, 3] $> 'a'
"aaa"
```

#### void
`void` 函数也包含在 `Data.Functor` 模块中
<p style="text-align: center;">void :: Functor f => f a -> f ()</p>

void 函数把一个函子内部的全部元素都变成空（`()`），`void x` 相当于 `() <$ x`：
```haskell
ghci> void [1, 2, 3]
[(), (), ()]
ghci> void (Just 2)
Just ()
```

---

## Applicative Functor
应用函子（Applicative Functor）是函子的升级版，它包含在 `Control.Applicative` 模块中。

fmap 进行的操作是将一个普通一元函数应用在一个函子内部。而如果要将一个包含函数的函子应用在另一个函子上，fmap 就处理不了了，但是应用函子的方法可以处理。应用函子的定义：
```haskell
class Functor f => Applicative f where
    pure :: a -> f a
    (<*>) :: f (a -> b) -> f a -> f b
```
应用函子要求实现两个函数：

- `pure` :: a -> f a，不难理解，pure 接收一个值，并将其放在默认的上下文/容器中。对于列表，pure = []；对于 Maybe，pure = Just
- `<*>` :: f (a -> b) -> f a -> f b，类似于 fmap :: (a -> b) -> f a -> f b，但不同的是 <\*> 的第一个参数的类型是 f (a -> b) 不是 a -> b。所以 <*> 的第一个参数是在上下文中的函数，而不是一个普通函数。换句话说，<\*> 接收一个装有函数的函子和另一个函子，应用函数后返回新的函子。

### Applicative Functor 实例
#### Maybe
Maybe 是一个应用函子：
```haskell
instance Applicative Maybe where
    pure = Just
    Nothing <*> _ = Nothing
    (Just f) <*> something = fmap f something
```

- `pure` 函数：将一个值放在默认的上下文中，而对于 Maybe，默认的上下文就是 Just，所以 pure x = Just x
- `<*>` 函数：将装有函数的函子中的函数应用另一个函子中
    - 第一个参数是 Nothing，即第一个函子不包含函数，那返回的结果就也会是 Nothing
    - 第一个参数是装有函数f的函子 Just f，将其中的函数f应用在函子 something 中，只需要将 f 提取出来使用 fmap 应用在函子 something 中即可

实际应用的例子：
```haskell
ghci> Just (+3) <*> Just 9
Just 12
ghci> pure (+3) <*> Just 9
Just 12
ghci> (+3) <$> Just 9
Just 12
ghci> Nothing <*> Just 9
Nothing
```
第一个例子，Just (+3) 是一个包含函数 (+3) 的函子，将其应用在函子 Just 9 中，将 Just (+3) 中的函数 (+3) 提取出来，应用在 Just 9 中，得到了 Just 12

第二个例子，可以发现，在这里 pure (+3) 和 Just (+3) 等效，因为 pure 将函数 (+3) 放在默认上下文中，也就是 Just 中了

而 <\*> 能做的不止这些，他可以连续传入更多函子作为参数，比如：
```haskell
ghci> pure (+) <*> Just 3 <*> Just 9
Just 12
ghci> pure (\x y z -> x + y + z) <*> Just 3 <*> Just 4 <*> Just 5
Just 12
```
<\*> 函数一样是默认左结合的，pure (+) <*> Just 3 <*> Just 9 相当于 (pure (+) <*> Just 3) <*> Just 9，而 pure (+) <*> Just 3 将 (+) 应用在Just 3 上，得到的就是 Just (+3) 一个包含函数的函子，又将其通过 <*> 应用在了 Just 9 上，得到了 Just 12:
```haskell
  pure (\x y z -> x + y + z) <*> Just 3 <*> Just 4 <*> Just 5
= (pure (\x y z -> x + y + z) <*> Just 3) <*> Just 4 <*> Just 5
= (Just (\y z -> 3 + y + z) <*> Just 4) <*> Just 5
= Just (\z -> 3 + 4 + z) <*> Just 5 = Just (+7) <*> Just 5
= Just 12
```
所以可以使用类似 pure f <*> x <*> y <*> ... 来将一个普通多元函数f应用在多个函子上。

而且 pure f <*> x 实际上先将普通函数f放在上下文中，然后执行 <*> 时再将其提取出来执行 fmap，所以它就相当于将普通函数应用在函子 x 上，即 fmap f x，也可以写成 f <$> x。所以常用的写法就是：
<p style="text-align: center;">f <$> x <*> y <*> ...</p>

#### []
列表也是一个应用函子：
```haskell
instance Applicative [] where
    pure x = [x]
    fs <*> xs = [f x | f <- fs, x <- xs]
```
- `pure` 函数：对于列表而言，一个值的最小上下文就是只包含这个值的列表 [x]
- `<*>` 函数：列表的 <*> 函数是通过列表推导来实现的。因为不同于 Maybe 的 Just 只包含一个值，列表可以包含很多值，第一个传入的列表中可能会包含很多函数，第二个传入的列表也会包含很多值，所以就需要先从第一个列表中取出一个函数然后依次应用在第二个列表的每个值中，再取出第一个列表中的第二个函数应用在第二个列表的每个值中……最终返回得到的所有结果的列表

使用例子：
```haskell
ghci> [(+3), (*2)] <*> [1, 2]
[4,5,2,4]
ghci> [(+), (*)]  <*>  [1, 2]  <*>  [3, 4]  
[4, 5, 5, 6, 3, 4, 6, 8]
```

#### IO
```haskell
instance Applicative IO where
    pure = return
    a <*> b = do
        f <- a
        x <- b
        return (f x)
```
也不难理解，pure 函数直接将传入的值 return，相当于放在了 IO 的上下文中。而 <*> 函数先将两个 IO 中内容提取出来，然后应用函数后 return，形成新的 IO 函子
```haskell
ghci> (++) <$> getLine <*> getLine
Line1
Line2
"Line1Line2"
```

#### (->) r
(->) r 同样也是一个应用函子，和函子的分析一样，先来分析它的 <*> 函数的类型签名：
<p style="text-align: center;"><*> :: f (a -> b) -> f a -> f b</p>

其中 f 为 (->) r，将其代入并替换为中缀：
<p style="text-align: center;"><*> :: (r -> a -> b) -> (r -> a) -> (r -> b)</p>

可以看出它接收两个函数 f :: r -> a -> b、g :: r -> a，返回另一个函数 h :: (r -> b)

那么返回的函数的输入为 r，输出为 b，所以先对输入应用函数 g 得到 a，然后在对 r 和 a 应用 f 得到 b，所以推测 <*> 函数的操作就是：
<p style="text-align: center;">\x -> f x (g x)</p>

于是：
```haskell
instance Applicative ((->) r) where
    pure x = (\_ -> x)
    f <*> g = \x -> f x (g x)
```
将一个值放在函数的上下文中，最小上下文就应该返回这个值本身，所以 pure 函数定义为 (\_ -> x)，即无论输入什么，都返回 x

应用函子的 <\*> 函数接收两个函子，返回一个新的函子。对于 (->) r，它接收两个函数，返回一个新的函数。具体例子：
```haskell
ghci> (+) <$> (+3) <*> (*100) $ 5
508
```
执行这句时发生了什么？：
```haskell
  (+) <$> (+3) <*> (*100) $ 5
= ((+) <$> (+3)) <*> (*100) $ 5
= ((+) . (+3)) <*> (*100) $ 5 = (\a -> (+) ((+3) a)) <*> (*100) $ 5
= (\a b -> (a + 3 + b)) <*> (*100) $ 5
= (\x -> x + 3 + ((*100) x)) $ 5
= (\x -> x + 3 + x * 100) $ 5
= 5 + 3 + 5 * 100 = 508
= (5 + 3) + (5 * 100)
```
所以就相当于先对输入分别执行 (+3) 和 (\*100)，然后将两个结果执行了 (+)

同样：
```haskell
ghci> (\x y z -> [x,y,z]) <$> (+3) <*> (*2) <*> (/2) $ 5  
[8.0,10.0,2.5]  
```
先对 5 分别执行 (+3)、(*2)、(/2)，然后将得到的三个结果传入 (\x y z -> [x,y,z]) 得到了最终的结果

```haskell
  f <$> g <*> h <*> i
= (\x -> f (g x) (h x) (i x))
```

#### ZipList
普通列表实现的 <*> 函数是将每个函数应用在所有值上，但还有一种实现方法是将每个函数应用在对应值上，因为同一个类型不能存在同一函数的两种实现形式，所以引入了一个新的列表 ZipList，包含在 `Control.Applicative` 模块中
```haskell
instance Applicative ZipList where
    pure x = ZipList (repeat x)
    ZipList fs <*> ZipList xs = ZipList (zipWith ($) fs xs)
```
但是 ZipList 并不是 Show 的实例，所以不能直接显示出来，要使用 `getZipList` 来获取它内部的列表：
```haskell
ghci> getZipList $ (+) <$> ZipList [1,2,3] <*> ZipList [100,100..]  
[101,102,103]
ghci> getZipList $ (,,) <$> ZipList "dog" <*> ZipList "cat" <*> ZipList "rat"  
[('d','c','r'),('o','a','a'),('g','t','t')]  
```

### Applicative Functor Laws
应用函子一般有四个定律，都是保证 pure 的正确性的：

1. `Identity law`：pure id <*> v = v
2. `Homomorphism`：pure f <*> pure x = pure (f x)
3. `Interchange`：u <*> pure v = pure ($ v) <*> u
4. `Composition`：u <*> (v <*> w) = pure (.) <*> u <*> v <*> w

### Intuition
理解应用函子的方式也是将其看作是计算上下文（context），比如要计算：

$$
[[\ \ g\ x_1\ x_2\ \cdots\ x_n\ \ ]]
$$

其中 $x_i$ 的类型是 $f\ t_i$，$f$ 是应用函子（看作上下文）。而函数 $g$ 的类型是：

$$
t_1\to t_2\to\cdots\to t_n\to t
$$

所以双括号（idiom brackets）的作用是将一个普通函数应用在包含在上下文中的参数上。$g\ x_1$ 可以通过 fmap 来执行，将 $g$ 提升（lift）到 $x_1$ 的上下文中，然后应用在 $x_1$ 上。但是 fmap 返回的结果是一个函子，换句话说，$g\ x_1$ 结果的类型是：

$$
f\ \ (t_2\to t_3\to\cdots\to t_n\to t)
$$

但是 fmap 并不能将上下文中的函数应用在上下文中的参数上，于是应用函子的 <*> 函数提供了这个方法，所以计算 $[[\ g\ x_1\ x_2\ \cdots\ x_n\ ]]$，只需要：
<p style="text-align: center;">g <$> x1 <*> x2 <*> ... <*> xn</p>

而 pure 函数的作用就是将一个不在上下文中的值（函数或参数）提升到上下文中，但不进行其他操作。比如参数 $x_2$ 如果不在上下文中，需要用 pure 提升到上下文中才能按上面计算：
<p style="text-align: center;">g <$> x1 <*> pure x2 <*> ... <*> xn</p>

### 常用函数
#### liftA & liftA2 & liftA3
<p style="text-align: center;">liftA :: Applicative f => (a -> b) -> f a -> f b</p>
<p style="text-align: center;">liftA2 :: Applicative f => (a -> b -> c) -> f a -> f b -> f c</p>
<p style="text-align: center;">liftA3 :: Applicative f => (a -> b -> c -> d) -> f a -> f b -> f c -> f d</p>

不难推测 liftA 就是 fmap，`liftA2 f x1 x2` 相当于 `f <$> x1 <*> x2`，`liftA3 f x1 x2 x3` 相当于 `f <$> x1 <*> x2 <*> x3`

#### <\* & \*>
类型类似函子的 `<$` 和 `$>`：
<p style="text-align: center;">(&lt;*) :: Applicative f => f a -> f b -> f a</p>
<p style="text-align: center;">(*>) :: Applicative f => f a -> f b -> f b</p>

<* 接收两个函子，如果两个函子中又一个为空，就返回空，否则返回的类型与第一个函子相同。\*> 反过来
```haskell
ghci> Just 3 <* Just 4
Just 3
ghci> Just 3 *> Just 4
Just 4
ghci> Nothing <* Just 3
Nothing
ghci> Nothing *> Just 3
Nothing
ghci> [1, 2, 3] <* [3, 4]
[1,1,2,2,3,3]
ghci> [1, 2, 3] *> [3, 4]
[3,4,3,4,3,4]
ghci> [] <* [1, 2, 3]
[]
ghci> [] *> [1, 2, 3]
[]
```

#### <**>
<p style="text-align: center;">(<**>) :: Applicative f => f a -> f (a -> b) -> f b</p>

接收的参数是 <\*> 反转过来的，即先接收一个参数函子，然后接收一个函数函子，在将其应用返回。但是和 flip(<\*>) 不同，它先取参数函子的每个参数，然后再取函数函子中的函数逐个应用：
```haskell
ghci> [(+1), (+2), (+3)] <*> [1, 2]
[2,3,3,4,4,5]
ghci> [1, 2] <**> [(+1), (+2), (+3)]
[2,3,4,3,4,5]
ghci> flip(<*>) [1, 2] [(+1), (+2), (+3)]
[2,3,3,4,4,5]
```

#### when & unless
<p style="text-align: center;">when :: Applicative f => Bool -> f () -> f ()</p>

传入的第一个是一个结果为 Bool 类型的测试，如果测试为 True，则调用第二个参数，否则返回 pure ()。（when 函数在上文 IO 操作中使用过）

unless 则与 when 相反，测试为 True 返回 pure ()

#### sequenceA
<p style="text-align: center;">sequenceA :: (Traversable t, Applicative f) => t (f a) -> f (t a)</p>

应用在列表上时，它的类型相当于：
<p style="text-align: center;">[f a] -> f [a]</p>

所以在列表上它的使用方法：
```haskell
ghci> sequenceA [Just 3, Just 2, Just 1]  
Just [3,2,1]  
ghci> sequenceA [Just 3, Nothing, Just 1]  
Nothing  
ghci> sequenceA [(+3),(+2),(+1)] 3  
[6,5,4]  
ghci> sequenceA [[1,2,3],[4,5,6]]  
[[1,4],[1,5],[1,6],[2,4],[2,5],[2,6],[3,4],[3,5],[3,6]]  
ghci> sequenceA [[1,2,3],[4,5,6],[3,4,4],[]]  
[]  
```
它在对同一个参数应用不同函数时很有用：
```haskell
ghci> map (\f -> f 7) [(>4), (<10), odd]  
[True,True,True]  
ghci> sequenceA [(>4), (<10), odd] 7  
[True,True,True]  
```

---

## Monad
单子（Monad）是对 Applicative Functor 的扩展（但是诞生比 Applicative 早），Functor 的 `<$>` 函数实现了将普通函数应用在上下文值上，Applicative 的 `<*>` 函数将上下文中函数应用在上下文值上。而 Monad 提供了一个函数 `>>=`（bind），将一个接收普通值返回上下文值的函数应用在上下文值上：
```haskell
class Applicative m => Monad m where
    (>>=) :: m a -> (a -> m b) -> m b
    (>>) :: m a -> m b -> m b
    return :: a -> m a
    m >> n = m >>= \_ -> n
    return = pure
```

- `return` 函数：和 `pure` 一样，只是有另一个名字
- `>>` 函数：提供了默认的实现方法，它的作用和 Applicative 的 *> 函数一样
- `>>=` 函数（bind）：比 Applicative 升级的函数，第一个参数是一个单子，第二个参数是一个接收值返回单子的函数，将这个函数应用在第一个参数单子中的值上，并返回得到的新单子

### Monad 实例
#### Maybe
Maybe 是一个单子实例，Applicative 已经为它实现了 return，因此只需要 >>= 函数：
```haskell
instance Monad Maybe where
    (Just x) >>= f = f x 
    Nothing  >>= _ = Nothing
```
根据定义就很容易实现 Maybe 的 >>= 函数了，而且也很好理解
```haskell
ghci> Just 1 >>= \x -> Just (x + 1)
Just 2
ghci> Just 1 >>= \x -> return (x + 1)
Just 2
ghci> Nothing >>= \x -> Just (x + 1)
Nothing
ghci> Just 1 >>= \x -> Just (x + 1) >> Nothing >>= \y -> Just (y + 1)
Nothing
```
最后一个例子中出现了 >> Nothing，这时 Nothing 前的部分全都相当于没用，因为 >> 操作符的左右两边只要有一个出现 Nothing，那整体就会是 Nothing。这个特性可以用于在中途随时判断失误，只要有一处失误，结果就会是 Nothing

#### []
列表也是一个单子：
```haskell
instance Monad [] where
    xs >>= f = concat (map f xs)
```
将这个函数应用在 xs 的每个值上，将返回的所有列表平铺成一个列表：
```haskell
ghci> [3,4,5] >>= \x -> [x,-x]  
[3,-3,4,-4,5,-5]  
ghci> [1,2] >>= \n -> ['a','b'] >>= \ch -> return (n,ch)  
[(1,'a'),(1,'b'),(2,'a'),(2,'b')]  
```

#### IO
IO 也是一个单子，但是实现方法比较深奥（逃

#### (->) r
(->) r 也是一个单子，和 Functor、Applicative 一样，先分析它的 >>= 类型签名：
<p style="text-align: center;">(>>=) :: (-> r) a -> (a -> (-> r) b) -> (-> r) b</p>
<p style="text-align: center;">(>>=) :: (r -> a) -> (a -> r -> b) -> (r -> b)</p>

也可以看出来，它接收两个函数 f :: r -> a、g :: a -> r -> b，然后返回一个新的函数 h :: r -> b

那么函数 h 接收一个类型为 r 的参数，返回一个类型为 b 的值。所以先对输入应用 f 得到类型为 a 的中间值，然后再将这个值和输入参数一起传入函数 g 得到结果。所以函数 h 的定义应该是：
<p style="text-align: center;">\x -> g (f x) x</p>

```haskell
instance Monad ((->) r) where
    f >>= g = \x -> g (f x) x
```
```haskell
ghci> (+3) >>= (+) $ 1
5
ghci> (+) <$> (+3) <*> id $ 1
5
```

### do-notation
Haskell 的 do 语句为链式的 >>= 应用提供了类似命令式（imperative style）的语法糖。比如 `a >>= \x -> b >> c >>= \y -> d`：
```haskell
a >>= \x ->
b >>
c >>= \y ->
d
```
其中有 abcd 四个值，可以看出 a 中内容绑定到了 x 上，c 中内容绑定到了 y 上。使用 do 语句来表示这个操作可以写成：
```haskell
do { x <- a 
   ;      b 
   ; y <- c 
   ;      d 
   }
```
其中的大括号和分号可以省略不写（挤在一行时不能省略）。do 语句也只是一个语法糖，它可以递归地转换成普通的 Monad 操作语句：

- `do e`：e
- `do { e; ... }`：e >> do { ... }
- `do { v <- e; ... }`：e >>= \v -> do { ... }
- `do { let ...; ... }`：let ... in do { ... }

#### ApplicativeDo
比如如下一个 do 语句：
```haskell
do x <- a 
   y <- b 
   z <- c 
   return (f x y z)
```
它可以转化成：
<p style="text-align: center;">a >>= \x -> b >>= \y -> c >>= \z -> return (f x y z)</p>

但是经过观察可以发现，整个语句实际上将函数 f 应用在了三个上下文中的值上，所以仅用 Applicative 的 <$> 和 <*> 完全可以实现：
<p style="text-align: center;">f <$> a <*> b <*> c</p>

而且在运行的时候 Applicative 的效率会比 Monad 高，所以 Haskell 会将 do 语句尽可能优先转换为 Applicative 的表示方法然后再计算

### Monad Laws
1. `Left identity`：return a >>= k      = k a
2. `Right identity`：m        >>= return = m
3. `Associativity`：(m >>= g) >>= h      = m >>= (\x -> g x >>= h)

前两个定律很好理解：

- 将 a 注入上下文之后绑定（bind）给函数 k(:: a -> m a)，相当于直接将 a 直接传入函数 k
- 将已经包含在上下文中的值绑定给 return 函数，相当于保持不变

第三个定律是结合律，把它写成更像结合律的表示方法是：
<p style="text-align: center;">(m >>= (\x -> g x)) >>= h <code>=</code> m >>= (\x -> g x >>= h)</p>

#### 组合运算符（>=>）形式
`Control.Monad` 模块中还定义了函数 `>=>`（Kleisli-composition operator）：
```haskell
infixr 1 >=>
(>=>) :: Monad m => (a -> m b) -> (b -> m c) -> (a -> m c)
f >=> g = \x -> f x >>= g
```
使用 >=> 运算符可以将两个用于绑定的函数结合在一起。用它表示的 Monad 定律更加清晰直观：

1. `Left identity`：return >=> f = f
2. `Right identity`：f >=> return = f
3. `Associativity`：(f >=> g) >=> h = f >=> (g >=> h)

#### do-notation 形式
Monad 的这三个定律还可以使用 do 语句来描述：

1. `Left identity`：
    ```haskell
    do { x' <- return x;
         f x'             =   do { f x } 
       }
    ```
2. `Right identity`：
    ```haskell
    do { x <- m; 
         return x         =   do { m }
       }
    ```
3. `Associativity`：
    ```haskell
    do { y <- do { x <- m;       do { x <- m;              do { x <- m;
                   f x                do { y <- f x;            y <- f x;
                 }           =             g y         =        g y
         g y                             }                    }
       }                            }
    ```

### Intuition
Monad 也可以很自然地看成 Applicative 的升级版，比如 Applicative 的操作全部是固定的，而 Monad 的操作可以在中途突然改变

同时 Monad 也完成了 Functor 和 Applicative 无法完成的操作。比如要用 fmap 和实现 >>= 函数（即达成操作 m a -> (a -> m b) -> m b），先假设 f :: a -> m b，那么 fmap f 的类型就会是 m a -> m (m b)，将 m a 应用在 fmap f 上会得到结果 m (m b)，而不是 m b。但是目前只可以使用 pure 将一个值装入上下文中（a -> m a），而没有一个函数可以从上下文中提取值（m a -> a）。那么就需要定义一个新的函数来实现这个操作的效果（m (m b) -> m b）。因此 Monad 的另一个等效的定义方法是：
```haskell
class Applicative m => Monad' m where
    join :: m (m a) -> m a 
    
    (>>=) :: m a -> (a -> m b) -> m b 
    x >>= f = join $ fmap f x
```
但是定义 >>= 函数会更为直观方便，所以 Haskell 采用了用 >>= 函数定义 Monad 的方法

同时 Haskell 还提供了 join 函数的定义：
```haskell
join :: Monad m => m (m a) -> m a 
join x = x >>= id
```

### 常用函数
#### liftM & ap
<p style="text-align: center;">liftM :: Monad m => (a -> b) -> m a -> m b</p>
<p style="text-align: center;">ap :: Monad m => m (a -> b) -> m a -> m b</p>

所以 liftM 其实就是 fmap、ap 就是 <*>，但是老版本的 GHC 定义 Monad 并没有 Functor、Applicative 的约束，所以实现了 liftM、ap，并且保留了这个名字

因此一个单子也可以通过 `pure = return`、`(<*>) = ap` 直接成为应用函子的实例

#### sequence
<p style="text-align: center;">sequence :: Monad m => [m a] -> m [a]</p>

sequence 的作用显而易见，而且在 IO 部分也使用到了。但是这个版本是在 `GHC.Base` 模块中定义的，还有一个更广泛的使用 Traversable 的定义在 `Data.Traversable` 模块中 

#### replicateM
<p style="text-align: center;">replicateM :: Applicative m => Int -> m a -> m [a]</p>

#### mapM & forM
<p style="text-align: center;">mapM :: Monad m => (a -> m b) -> [a] -> m [b]</p>
<p style="text-align: center;">forM :: Monad m => [a] -> (a -> m b) -> m [b]</p>

forM 的用法在 IO 部分已经说过，mapM 和 forM 都在 `Data.Traversable` 模块中有广泛版本

还有一些其他的函数：filterM、zipWithM、foldM、forever，通过名字就可以看出用法，是将原来仅使用与列表的函数提升至可以适用于所有单子

并且在函数名后加下划线，比如 sequence_、mapM_，会忽略返回值（最终结果为 `m ()`）

#### =<< & >=> & <=<
（`>=>` 操作符在上面 [Monad Laws](#_18) 部分已经给出了定义）
- x >>= f = f =<< x 
- f >=> g = g <=< f 

---

## MonadFail
MonadFail 定义在 `Control.Monad.Fail` 模块中：
```haskell
class Monad m => MonadFail m where
    fail :: String -> m a 
```
它只要求在 Monad 的基础上实现 fail 函数，接收一个字符串返回一个单子。这会使在 do 语句中产生错误时直接变为错误值（空值）使最终的返回值为错误值

### MonadFail 实例
```haskell
instance MonadFail Maybe where
    fail _ = Nothing

instance MonadFail [] where
    fail _ = []

instance MonadFail IO where
    fail = failIO
```
Maybe 和 [] 的 fail 函数都与第一个参数无关，直接返回空值（Nothing、[]）；而 IO 的 fail 函数直接使用 failIO，实现方法也是深奥（接着逃
```haskell
exampleFail :: Maybe Char 
exampleFail = do
    (x:xs) <- Just ""
    return x 

ghci> exampleFail
Nothing
```
在这个例子的 do 语句中，在提取 Just "" 中的值时用了模式匹配，但是因为其内容为空字符串，x:xs 匹配会出现错误，这时就会触发 fail 函数直接返回 Nothing

### MonadFail Law
- fail s >>= m = fail s 

---

## Semigroup
半群（semigroup）是一个集合 $S$，它需要指定一个二元运算符 $\oplus$，并且满足

$$
a\oplus b \in S\quad a, b\in S
$$

以及结合（associative）律：

$$
(a\oplus b)\oplus c = a\oplus (b\oplus c)
$$

这个二元运算符在 Haskell 的 Semigroup 中被定义为 `<>` 函数：
```haskell
class Semigroup a where
    (<>) :: a -> a -> a 

    sconcat :: NonEmpty a -> a 
    sconcat (a :| as) = go a as where 
        go b (c:cs) = b <> go c cs 
        go b []     = b
    
    stimes :: Integarl b => b -> a -> a 
    stimes = ...
```
除此之外还有 `sconcat` 和 `stimes` 函数，都给出了默认实现。对于列表，<> 相当于 (++)，stimes 相当于 concat . replicate：
```haskell
ghci> [1, 2] <> [3, 4]
[1,2,3,4]
ghci> sconcat $ fromList [[1, 2], [3, 4]]
[1,2,3,4]
ghci> stimes 3 [1, 2]
[1,2,1,2,1,2]
```

### Semigroup Law
- (x <> y) <> z = x <> (y <> z)

### 补：NonEmpty 
NonEmpty 表示非空列表，定义是：
```haskell
data NonEmpty a = a :| [a] deriving (Eq, Ord)
```
使用一个元素和一个列表用 `:|` 连接就可以生成一个 NonEmpty 类型的列表

`Data.List.NonEmpty` 模块中实现了很多普通列表有的函数，需要 qualified import 后调用，使用 fromList、toList 函数可以在普通列表和非空列表之间转换
```haskell
ghci> import qualified Data.List.NonEmpty as NE
ghci> arr = NE.fromList [1, 2, 3]
ghci> arr
1 :| [2,3]
ghci> NE.head arr 
1
ghci> NE.tail arr 
[2,3]
```

---

## Monoid 
幺半群（Monoid）是一个有单位元素 $e$ 的半群，即 $e$ 满足：

$$
e\oplus x = x\oplus e = x
$$

```haskell
class Semigroup a => Monoid a where 
    mempty  :: a 
    
    mappend :: a -> a -> a 
    mappend = (<>)

    mconcat :: [a] -> a 
    mconcat = foldr mappend mempty 
```
可以看出 Monoid 要求了三个函数，其中最少只需要 `mempty`，它直接返回一个值，表示单位元素。`mappend` 即 Semigroup 中的 <> 运算符，`mconcat` 也提供了默认实现

### Monoid 实例
#### [a]
因为 Monoid 的实例是一个具体类型，而不是像 Functor 等一样等类型构造器，所以 [] 并不是 Monoid 的实例，但是具体类型 [a] 是一个幺半群：
```haskell
instance Semigroup [a] where 
    (<>) = (++)

instance Monoid [a] where 
    mempty = [] 
    mconcat xss = [x | xs <- xss, x <- xs]
```
列表的单位元素（mempty）就是空列表 []，运算符就是合并列表 (++)，mconcat 也用列表推导重新实现提高效率
```haskell
ghci> mempty :: [Int] 
[]
ghci> [1, 2] <> [3, 4]
[1,2,3,4]
ghci> [1, 2] `mappend` [3, 4]
[1,2,3,4]
ghci> mconcat [[1,2], [3,4]]
[1,2,3,4]
```

#### Ordering 
```haskell
instance Semigroup Ordering where
    LT <> _ = LT
    EQ <> y = y
    GT <> _ = GT

instance Monoid Ordering where
    mempty = EQ
```
主要可以用于比较字典序：
```haskell
ghci> mconcat (zipWith compare "abcd" "acbd")
LT
```

#### Sum & Product 
对于数字，加法和乘法都满足结合律，所以对于 Num，有两种实现 Monoid 的方式，但是不能为同一类型设置两种实例方式，所以 `Data.Monoid` 中提供了两个包装器———— Sum 和 Product：
```haskell
newtype Sum a = Sum {getSum :: a} deriving (...)
newtype Product a = Product {getProduct :: a} deriving (...)
```
它们使用 Sum 或 Product 来包装起一个数字，可以通过 getSum 或 getProduct 来获取其中的值

对于加法，二元操作为 (+)，单位元素为 0；对于乘法，二元操作为 (*)，单位元素为 1:
```haskell
instance Num a => Semigroup (Sum a) where
    (<>) = coerce ((+) :: a -> a -> a)

instance Num a => Monoid (Sum a) where
    mempty = Sum 0

instance Num a => Semigroup (Product a) where
    (<>) = coerce ((*) :: a -> a -> a)

instance Num a => Monoid (Product a) where
    mempty = Product 1
```
```haskell
ghci> Sum 5 <> Sum 6 <> Sum 10
Sum {getSum = 21}
ghci> getSum . mconcat . fmap Sum $ [5, 6, 10]
21
ghci> Product 5 <> Product 6 <> Product 10
Product {getProduct = 300}
ghci> getProduct . mconcat . fmap Product $ [5, 6, 10]
300
```

#### All & Any
和数字一样，布尔值也有两种实现 Monoid 的方式，因此 `Data.Monoid` 模块中也提供了两个包装器，分别实现了这两种 Monoid：
```haskell
newtype All = All { getAll :: Bool } deriving (...)

instance Semigroup All where
        (<>) = coerce (&&)

instance Monoid All where
        mempty = All True


newtype Any = Any { getAny :: Bool } deriving (...)

instance Semigroup Any where
        (<>) = coerce (||)

instance Monoid Any where
        mempty = Any False
```
```haskell
ghci> getAll (All True <> mempty <> All False)
False
ghci> getAll (mconcat (map (\x -> All (even x)) [2,4,6,7,8]))
False
ghci> getAny (Any True <> mempty <> Any False)
True
ghci> getAny (mconcat (map (\x -> Any (even x)) [2,4,6,7,8]))
True
```

#### Monoid a => Maybe a 
如果 a 是一个(幺)半群，那么 Maybe a 也是一个幺半群，单位元就是 Nothing：
```haskell
instance Semigroup a => Semigroup (Maybe a) where
    Nothing <> b       = b
    a       <> Nothing = a
    Just a  <> Just b  = Just (a <> b)

instance Semigroup a => Monoid (Maybe a) where
    mempty = Nothing
```
```haskell
ghci> Nothing <> Just "andy"
Just "andy"
ghci> Just LT <> Nothing
Just LT
ghci> Just (Sum 3) <> Just (Sum 4) 
Just (Sum {getSum = 7})
```

#### First & Last 
对于 Maybe 也有两种实现 Monoid 的方法，即 <> 操作每次恒取左边和每次恒取右边（在没有 Nothing 的情况下），所以 `Data.Monoid` 模块中也提供了两个新的包装器：First 和 Last：
```haskell
newtype First a = First { getFirst :: Maybe a } deriving (...)

instance Semigroup (First a) where
    First Nothing <> b = b
    a             <> _ = a

instance Monoid (First a) where
    mempty = First Nothing


newtype Last a = Last { getLast :: Maybe a } deriving (...)

instance Semigroup (Last a) where
    a <> Last Nothing = a
    _ <> b            = b

instance Monoid (Last a) where
    mempty = Last Nothing
```
```haskell
ghci> getFirst (First (Just "hello") <> First Nothing <> First (Just "world"))
Just "hello"
ghci> getLast (Last (Just "hello") <> Last Nothing <> Last (Just "world"))
Just "world"
ghci> getFirst . mconcat . map First $ [Nothing, Just 9, Just 10]  
Just 9
ghci> getLast . mconcat . map Last $ [Nothing, Just 9, Just 10]  
Just 10
```

#### Min & Max 
对于有界的类型，也有两种实现 Monoid 的方式，每次二元操作都取最小或最大。`Data.Semigroup` 模块中提供了两个包装其器：Min 和 Max：
```haskell
newtype Min a = Min { getMin :: a } deriving (...)

instance Ord a => Semigroup (Min a) where
    (<>) = coerce (min :: a -> a -> a)

instance (Ord a, Bounded a) => Monoid (Min a) where
    mempty = maxBound


newtype Max a = Max { getMax :: a } deriving (...)

instance Ord a => Semigroup (Max a) where
    (<>) = coerce (max :: a -> a -> a)

instance (Ord a, Bounded a) => Monoid (Max a) where
    mempty = minBound
```
```haskell
ghci> Min 3 <> Min 5
Min {getMin = 3}
ghci> Max 3 <> Max 5
Max {getMax = 5}
ghci> getMin . mconcat . map Min $ [1,2,3] :: Int
1
ghci> getMax . mconcat . map Max $ [1,2,3] :: Int
3
```

#### 元组
当元组内的所有元素都是幺半群时，整个元组也是一个幺半群：
```haskell
instance (Semigroup a, Semigroup b) => Semigroup (a, b) where
        (a,b) <> (a',b') = (a<>a',b<>b')
        stimes n (a,b) = (stimes n a, stimes n b)

instance (Monoid a, Monoid b) => Monoid (a,b) where
        mempty = (mempty, mempty)
```
```haskell 
ghci> mconcat $ map (\x -> (Min x, Max x)) [1..10] :: (Min Int, Max Int)
(Min {getMin = 1},Max {getMax = 10})
```

### Monoid Laws 
- mempty <> x = x
- x <> mempty = x
- (x <> y) <> z = x <> (y <> z)

---

## Monoidal classes 
Applicative、Monad、Arrow 都有有幺半群性质的子类型类，分别是 Alternative、MonadPlus、ArrowPlus

### Alternative 
```haskell
class Applicative f => Alternative f where
    -- | The identity of '<|>'
    empty :: f a
    -- | An associative binary operation
    (<|>) :: f a -> f a -> f a

    some :: f a -> f [a]
    some v = (:) <$> v <*> many v
    many :: f a -> f [a]
    many v = some v <|> pure []
```
其中 empty 是幺半群中的单位元素，<|> 是幺半群中的二元运算符。some 和 many 是两个函数（~~意义还不懂~~）

#### Alternative 实例
##### []
```haskell 
instance Alternative [] where
    empty = []
    (<|>) = (++)
```
和 Monoid 一样，单位元素是空列表，二元运算是列表合并
```haskell
ghci> [1,2,3] <|> empty <|> [4,5]
[1,2,3,4,5]
ghci> some []
[]
ghci> many []
[[]]
```

##### Maybe
```haskell
instance Alternative Maybe where
    empty = Nothing
    Nothing <|> r = r
    l       <|> _ = l
```
Maybe 作为 Alternative 的单位元素是 Nothing，二元运算是始终取左边（当左边不为 Nothing 时）
```haskell 
ghci> Nothing <|> Just 1 <|> Just 2 
Just 1 
ghci> some Nothing
Nothing 
ghci> many Nothing 
Just []
```
##### ZipList 
```haskell
instance Alternative ZipList where
   empty = ZipList []
   ZipList xs <|> ZipList ys = ZipList (xs ++ drop (length xs) ys)
```
```haskell 
<>getZipList $ ZipList [1,2] <|> ZipList [3,4,5,6]
[1,2,5,6]
<>getZipList $ ZipList [1,2,3,4] <|> ZipList [3,4,5,6]
[1,2,3,4]
```

#### Alternative Laws 
- `Monoid laws`:
    ```haskell 
    empty <|> x = x 
    x <|> empty = x 
    (x <|> y) <|> z = x <|> (y <|> z)
    ```
- `Left zero law`：empty <*> f = empty 

以上的定律是都满足都，下面的定律只有部分满足：

- `Right zero law`：f <*> empty = empty （大部分包括 Maybe、[] 满足，IO 不满足）
- `Left distribution`：(a <|> b) <*> c = (a <*> c) <|> (b <*> c) （Maybe、[] 满足，IO 及大部分 parsers 不满足）
- `Right distribution`：a <*> (b <|> c) = (a <*> b) <|> (a <*> c) （大部分不满足，但 Maybe 满足）
- `Left catch`：(pure a) <|> x = pure a （Maybe、IO、parsers 满足，但 [] 不满足）

#### 常用函数
- `asum` :: (Foldable t, Alternative f) => t (f a) -> f a，相当于 foldr (<|>) empty：
    ```haskell 
    ghci> asum [Nothing, Just 5, Just 3]
    Just 5
    ghci> asum [[2],[3],[4,5]]
    [2,3,4,5]
    ```
- `guard` :: (Alternative f) => Bool -> f ()：
    ```haskell 
    guard True  = pure ()
    guard False = empty 
    ```

### MonadPlus 
```haskell 
class (Alternative m, Monad m) => MonadPlus m where
   mzero :: m a
   mzero = empty

   mplus :: m a -> m a -> m a
   mplus = (<|>)
```

#### MonadPlus实例
[]、Maybe 都是 MonadPlus 的实例，mzero 和 mplus 都由 Alternative 实现

#### MonadPlus Laws 
- `Monoid laws`
- `Left zero`：mzero >>= f = mzero
- `Right zero`：m >> mzero = mzero 

#### 常用函数
- `msum` = asum 
- `mfilter`：
    ```haskell 
    mfilter p ma = do
        a <- ma
        if p a then return a else mzero
    ```

### ArrowPlus 
ArrowZero 和 ArrowPlus 分别为 Arrow 设置了 Monoid 中的单位元素和二元运算符，使之成为了一个幺半群：
```haskell 
class Arrow arr => ArrowZero arr where
    zeroArrow :: b `arr` c

class ArrowZero arr => ArrowPlus arr where
    (<+>) :: (b `arr` c) -> (b `arr` c) -> (b `arr` c)
```

---

## 一些其它 Typeclasses
### Foldable
Foldable 是表示可以折叠（fold）的类型类，在 `Data.Foldable` 中定义，这使得和 fold 相关的函数可以用在任意 Foldable 的实例类型上。它的定义是：
```haskell 
class Foldable t where
    fold     :: Monoid m => t m -> m
    foldMap  :: Monoid m => (a -> m) -> t a -> m
    foldMap' :: Monoid m => (a -> m) -> t a -> m
    foldr    :: (a -> b -> b) -> b -> t a -> b
    foldr'   :: (a -> b -> b) -> b -> t a -> b
    foldl    :: (b -> a -> b) -> b -> t a -> b
    foldl'   :: (b -> a -> b) -> b -> t a -> b
    foldr1   :: (a -> a -> a) -> t a -> a
    foldl1   :: (a -> a -> a) -> t a -> a
    toList   :: t a -> [a]
    null     :: t a -> Bool
    length   :: t a -> Int
    elem     :: Eq a => a -> t a -> Bool
    maximum  :: Ord a => t a -> a
    minimum  :: Ord a => t a -> a
    sum      :: Num a => t a -> a
    product  :: Num a => t a -> a
    {-# MINIMAL foldMap | foldr #-}
```
最少只要实现 `foldr` 和 `foldMap` 其中之一就可以使一个类型成为 Foldable 的实例，其它的函数都有由这两个函数提供的默认实现，而且这两个函数之间也有相互实现。因此只要实现 foldr 或 foldMap 一个函数就可以使用所有其它 Foldable 中的函数。foldr 函数在前面已经有学过，foldMap 的例子是：
```haskell 
ghci> foldMap Sum [1, 3, 5]
Sum {getSum = 9}
ghci> foldMap Product [1, 3, 5]
Product {getProduct = 15}
ghci> foldMap (replicate 3) [1, 2, 3]
[1,1,1,2,2,2,3,3,3]
```

#### Foldable 实例
[]、Maybe、Either a、(,) a 都是 Foldable 的实例，标准容器库中的 Map、Set 等也都是 Foldable 的实例。也可以自定义二叉树类型，并使其成为 Foldable 的实例：
```haskell 
data Tree a = Empty | Leaf a | Node (Tree a) a (Tree a)

instance Foldable Tree where 
    foldMap :: Monoid m => (a -> m) -> Tree a -> m
    foldMap f Empty        = mempty
    foldMap f (Leaf x)     = f x
    foldMap f (Node l k r) = foldMap f l `mappend` f k `mappend` foldMap f r
```

#### 常用函数
- `asum` :: (Alternative f, Foldable t) => t (f a) -> f a，用 <|> 逐个连接所有元素
- `sequenceA_` :: (Applicative f, Foldable t) => t (f a) -> f ()，由于丢弃结果，所以 Foldable t 就可以满足；因此不同于 sequenceA 需要 Traversable
- `traverse_` :: (Applicative f, Foldable t) => (a -> f b) -> t a -> f ()
- `for_` :: (Applicative f, Foldable t) => t a -> (a -> f b) -> f ()

### Traversable
Traversable 是表示可遍历的类型类，在 `Data.Traversable` 模块中定义，它是 Foldable 的升级版，同时也是一个 Functor，它的定义是：
```haskell 
class (Functor t, Foldable t) => Traversable t where 
    traverse  :: Applicative f => (a -> f b) -> t a -> f (t b)
    sequenceA :: Applicative f => t (f a) -> f (t a)
    mapM      ::       Monad m => (a -> m b) -> t a -> m (t b)
    sequence  ::       Monad m => t (m a) -> m (t a)
    {-# MINIMAL traverse | sequenceA #-}
```
最少只需要实现 traverse 函数或者 sequenceA 函数。其中各个函数的功能通过类型签名也都能推测出来。但是其中 mapM 就是 traverse，sequence 就是 sequenceA，它们存在只是历史遗留

#### Traversable 实例
```haskell 
instance Traversable Maybe where
    traverse _ Nothing = pure Nothing
    traverse f (Just x) = Just <$> f x

instance Traversable [] where
    {-# INLINE traverse #-}
    traverse f = foldr cons_f (pure [])
      where cons_f x ys = liftA2 (:) (f x) ys

instance Traversable (Either a) where
    traverse _ (Left x) = pure (Left x)
    traverse f (Right y) = Right <$> f y

instance Traversable ((,) a) where
    traverse f (x, y) = (,) x <$> f y

...
```
上面的 Tree 也可以成为 Traversable 的实例：
```haskell 
instance Functor Tree where
    fmap :: (a -> b) -> Tree a -> Tree b
    fmap     g Empty        = Empty
    fmap     g (Leaf x)     = Leaf $ g x
    fmap     g (Node l x r) = Node (fmap g l)
                                   (g x)
                                   (fmap g r)

instance Traversable Tree where
    traverse :: Applicative f => (a -> f b) -> Tree a -> f (Tree b) 
    traverse g Empty        = pure Empty
    traverse g (Leaf x)     = Leaf <$> g x
    traverse g (Node l x r) = Node <$> traverse g l
                                   <*> g x
                                   <*> traverse g r
```

#### Traversable Laws
Traversable 也有两条定律：
1. traverse Identity = Identity
2. traverse (Compose . fmap g . f) = Compose . fmap (traverse g) . traverse f 

其中 Identity 和 Compose 分别定义在 `Data.Functor.Identity` 和 `Data.Functor.Compose` 两个模块中：
```haskell 
newtype Identity a = Identity { runIdentity :: a } deriving (...)
newtype Compose f g a = Compose { getCompose :: f (g a) } deriving (...)
```

### Bifunctor
Functor 的实例的 kind 都是 \* -> \*，因此 fmap 只能将一个函数映射到一个值上。而 Bifunctor（在 `Data.Bifunctor` 模块中定义）的实例的 kind 是 \* -> \* -> \*，而且它的 bimap 可以同时将两个函数映射到两个值上：
```haskell 
class Bifunctor p where 
    bimap  :: (a -> b) -> (c -> d) -> p a c -> p b d 
    first  :: (a -> b) -> p a c -> p b c 
    second :: (b -> c) -> p a b -> p a c 
    {-# MINIMAL bimap | first, second #-}
```
同时 bimap 和 first,second 之间也可以相互转换：
```haskell 
bimap f g = first f . second g

first  f = bimap f id
second g = bimap id g
```
对于 Functor，((,) e) 和 Either e 才是 Functor 的实例，因为他们是 \* -> \*。但是对于 Bifunctor，(,) 和 Either 就是 Bifunctor 的实例：
```haskell 
ghci> bimap (+1) length (4, [1,2,3])
(5,3)
```

#### Bifunctor Laws
1. bimap id id = id
    first id = id
    second id = id
2. bimap (f . g) (h . i) = bimap f h . bimap g i
    first  (f . g) = first f  . first g
    second (f . g) = second f . second g

### Category 
Haskell 中的 Category 将一般的函数推广到了普遍的态射上，它在 `Control.Category` 模块中，定义是：
```haskell 
class Category cat where 
    id  :: cat a a 
    (.) :: cat b c -> cat a b -> cat a c
```
它的实例有 `(->)` 和 `Kleisli m`：
```haskell 
instance Category (->) where
    id = GHC.Base.id
    (.) = (GHC.Base..)
```
Kleisli 是一个范畴，用来表示函数 a -> m b，Haskell 中，它在 `Control.Arrow` 模块中定义：
```haskell 
newtype Kleisli m a b = Kleisli { runKleisli :: a -> m b }

instance Monad m => Category (Kleisli m) where
    id :: Kleisli m a a
    id = Kleisli return

    (.) :: Kleisli m b c -> Kleisli m a b -> Kleisli m a c
    Kleisli g . Kleisli h = Kleisli (h >=> g)
```
Category 要满足的定律只有 id 是 (.) 操作的单位元，以及 (.) 操作是可结合的

同时 Category 还提供了两个函数 `<<<` 和 `>>>`：
```haskell 
(<<<) :: Category cat => cat b c -> cat a b -> cat a c
(<<<) = (.)

(>>>) :: Category cat => cat a b -> cat b c -> cat a c 
f >>> g = g . f 
```

### Arrow 
Arrow 将函数进一步抽象化，它定义在 `Control.Arrow` 模块中：
```haskell 
class Category a => Arrow a where 
    arr    :: (b -> c) -> a b c 
    first  :: a b c -> a (b, d) (c, d)
    second :: a b c -> a (d, b) (d, c)
    (***)  :: a b c -> a b' c' -> a (b, b') (c, c')
    (&&&)  :: a b c -> a b c' -> a b (c, c')
    {-# MINIMAL arr, (first | (***)) #-}
```
其中：

- `arr` 函数将一个函数变成一个 Arrow
- `first` 函数将一个 Arrow 变成一个二元组间的 Arrow，且只会对一个元素进行操作，第二个元素保持不变
- `second` 函数与 first 相反，第一个元素保持不变
- `***` 函数是 Arrow 之间的 parallel composition，对于函数: (g *** h) (x, y) = (g x, h y)
- `&&&` 函数是 Arrow 之间的 fanout composition，对于函数: (g &&& h) x = (g x, h x)

它的实例也有 (->) 和 Kleisli：
```haskell 
instance Arrow (->) where
  arr :: (b -> c) -> (b -> c)
  arr g = g

  first :: (b -> c) -> ((b,d) -> (c,d))
  first g (x,y) = (g x, y)

instance Monad m => Arrow (Kleisli m) where
  arr :: (b -> c) -> Kleisli m b c
  arr f = Kleisli (return . f)

  first :: Kleisli m b c -> Kleisli m (b,d) (c,d)
  first (Kleisli f) = Kleisli (\ ~(b,d) -> do c <- f b
                                              return (c,d) )
```
常用函数：
```haskell 
returnA :: Arrow a => a b b
returnA = arr id

(^>>) :: Arrow a => (b -> c) -> a c d -> a b d
f ^>> a = arr f >>> a

(>>^) :: Arrow a => a b c -> (c -> d) -> a b d
a >>^ f = a >>> arr f

(<<^) :: Arrow a => a c d -> (b -> c) -> a b d
a <<^ f = a <<< arr f

(^<<) :: Arrow a => (c -> d) -> a b c -> a b d
f ^<< a = arr f <<< a
```

#### Arrow notation
类似 do-notation，Arrow 也提供了一套方便的语句：
```haskell 
proc x -> do 
    y <- action1 -< ... 
    z <- action2 -< ...
    returnA -< ...
```
其中 proc 代替了 lambda 表达式中的斜杠 \，-< 右边的为输入，左边的为接收输入的函数。比如，下面三种写法达成的效果是一样的：
```haskell 
f :: Int -> (Int, Int)
f = \x ->
    let y  = 2 * x
        z1 = y + 3
        z2 = y - 5
    in (z1, z2) 
-- ghci> f 10 
-- (23,15)

fM :: Int -> Identity (Int, Int)
fM = \x -> do
    y  <- return (2 * x)
    z1 <- return (y + 3)
    z2 <- return (y - 5)
    return (z1, z2)

-- ghci> runIdentity (fM 10)
-- (23,15)

fA :: Int -> (Int, Int)
fA = proc x -> do
    y  <- (2 *) -< x
    z1 <- (+ 3) -< y
    z2 <- (subtract 5) -< y
    returnA -< (z1, z2)

-- ghci> fA 10
-- (23,15)
```

#### ArrowChoice
```haskell 
class Arrow a => ArrowChoice a where
    left :: a b c -> a (Either b d) (Either c d)
    left = (+++ id)

    right :: a b c -> a (Either d b) (Either d c)
    right = (id +++)

    (+++) :: a b c -> a b' c' -> a (Either b b') (Either c c')
    f +++ g = left f >>> arr mirror >>> left g >>> arr mirror
      where
        mirror :: Either x y -> Either y x
        mirror (Left x) = Right x
        mirror (Right y) = Left y

    (|||) :: a b d -> a c d -> a (Either b c) d
    f ||| g = f +++ g >>> arr untag
      where
        untag (Left x) = x
        untag (Right y) = y

instance ArrowChoice (->) where
    left f = f +++ id
    right f = id +++ f
    f +++ g = (Left . f) ||| (Right . g)
    (|||) = either

instance Monad m => ArrowChoice (Kleisli m) where
    left f = f +++ arr id
    right f = arr id +++ f
    f +++ g = (f >>> arr Left) ||| (g >>> arr Right)
    Kleisli f ||| Kleisli g = Kleisli (either f g)
```

#### ArrowZero & ArrowPlus 
```haskell
class Arrow a => ArrowZero a where
    zeroArrow :: a b c

class ArrowZero a => ArrowPlus a where
    (<+>) :: a b c -> a b c -> a b c

instance MonadPlus m => ArrowZero (Kleisli m) where
    zeroArrow = Kleisli (\_ -> mzero)

instance MonadPlus m => ArrowPlus (Kleisli m) where
    Kleisli f <+> Kleisli g = Kleisli (\x -> f x `mplus` g x)
```

#### 例子
```haskell 
ghci> runKleisli ((Kleisli (\x -> [x * 2])) <+> (Kleisli (\x -> [x, -x]))) 2
[4,2,-2]
ghci> either (+2) (*3) (Left 3)
5
ghci> either (+2) (*3) (Right 3)
9
ghci> (+2) ||| (*3) $ (Left 3)
5
ghci> (+2) +++ (*3) $ (Left 3)
Left 5
ghci> (+2) ||| (*3) $ (Right 3)
9
ghci> (+2) +++ (*3) $ (Right 3)
Right 9
ghci> left (+2) (Left 3)
Left 5
ghci> right (*3) (Right 3)
Right 9
ghci> left (+2) (Right 3)
Right 3
ghci> right (*3) (Left 3)
Left 3
ghci> runKleisli ((Kleisli (\x -> [x * 2])) ||| (Kleisli (\x -> [x, -x]))) (Left 3)
[6]
ghci> runKleisli ((Kleisli (\x -> [x * 2])) ||| (Kleisli (\x -> [x, -x]))) (Right 3)
[3,-3]
ghci> runKleisli ((Kleisli (\x -> [x * 2])) +++ (Kleisli (\x -> [x, -x]))) (Left 3)
[Left 6]
ghci> runKleisli ((Kleisli (\x -> [x * 2])) +++ (Kleisli (\x -> [x, -x]))) (Right 3)
[Right 3,Right (-3)]
```

---

## Haskell 与范畴论 
Haskell 中的函子单子等都与范畴论（category theory）有很多联系，所以打算简单了解一下范畴论的相关内容。

> **范畴论**是数学的一门学科，以抽象的方法处理数学概念，将这些概念形式化成一组组的“物件”及“态射”。数学中许多重要的领域可以形式化为范畴。使用范畴论可以令这些领域中许多难理解、难捉摸的数学结论更容易叙述证明。
> <div style="text-align: right">———— 维基百科</div>

### 范畴（Category）
范畴本质上是一个简单的集合，一个范畴 $\mathbf{C}$ 包含三个组成成分：

- 一个类 $\mathrm{ob}(\mathbf{C})$：其中元素称为**对象（objects）**
- 一个类 $\mathrm{hom}(\mathbf{C})$：其中元素称为**态射（morphisms）**（或**箭号（arrows）**）：每个态射连接了两个对象：源对象（source object）、目标对象（target object）。如果 $f$ 是从源对象 $A$ 到目标对象 $B$（$A, B\in \mathrm{ob}(\mathbf{C})$）的态射，那么记为 $f : A\to B$
- 一个二元运算，称为态射**复合（composition）**：两个态射 $g : A\to B$、$f : B\to C$ 的复合记为 $f\circ g : A\to C$<br/>
  在 Haskell 和大部分数学理论中都是从右向左计算，即 $f\circ g$ 中是先计算 $g : A\to B$ 再计算 $f : B\to C$

许多东西都可以组成范畴。比如:
???+ example "例"

    &emsp;$\mathbf{Set}$ 是一个范畴，对象为所有集合，态射为集合之间的函数，复合即函数之间的复合

    &emsp;$\mathbf{Grp}$ 是一个范畴，对象为所有群，态射为群同态（group homomorphisms），例如对于群 $(G,*)$ 和 $(H,\cdot )$，有群同态 $h : (G,*)\to  (H,\cdot )$，则需要对于 $G$ 中的任意元素 $u,v$ 满足

    $$h(u*v)=h(u)\cdot h(v)$$

!!! warning "**注意**"
    态射不必须为函数；而且可以存在源对象和目标对象都相同的不同态射

#### 范畴公理
每个范畴都需要满足三条定律：

1. 态射复合需要满足**结合律（associativity）**：$f\circ (g\circ h) = (f\circ g)\circ h$
2. 范畴在复合操作下是**闭合的（closed）**：<br/>
  &emsp;&emsp;&emsp;如果范畴 $\mathbf{C}$ 中存在态射 $f : B\to C$、$g : A\to B$，那么范畴 $\mathbf{C}$ 中也一定存在态射 $h : A\to C$，且 $h=f\circ g$
3. 每个对象都需要有**单位态射（identity morphisms）**：<br/>
  &emsp;&emsp;&emsp;对于范畴$\mathbf{C}$中的对象$A$，一定存在单位态射$\mathrm{id}_A : A\to A$，且对于每个态射$g : A\to B$，一定有： $g\circ\mathrm{id}_A = \mathrm{id}_B\circ g = g$

#### $\mathbf{Hask}$ 范畴
范畴 $\mathbf{Hask}$ 的对象为 Haskell 中的类型（types），态射是 Haskell 中的函数，复合运算是 `(.)`。即从类型 A 到类型 B 的函数 f :: A -> B 就是 $\mathbf{Hask}$ 范畴中的一个态射。而函数 f :: B -> C 、g :: A -> B 的组合 f . g 就是一个新的函数 h :: A -> C。

对于三条定律：

1. 第一条显然满足：f . (g . h) = (f . g) . h
2. 第二条也显然满足，如果有函数 f :: B -> C 、g :: A -> B，一定有函数 h = (f . g) :: A -> C 
3. 对于第三条定律，Haskell 中存在单位函数 id ，但 id 是多态（polymorphic）的，要为其指定类型使其变成单态（monomorphic）的。比如态射 $\mathrm{id}_A$ 在 Haskell 中就可以表示为 id :: A -> A。并且显然满足第三条定律（其中 f :: A -> B）：
  <p style="text-align: center;">(id :: B -> B) . f = f . (id :: A -> A) = f</p>

### 函子（Functors）
一个范畴中的态射将两个对象联系起来，而函子则会将两个范畴联系起来。换句话说，函子就是从一个范畴到另一个范畴的变换。比如对于范畴 $\mathbf{C}$、$\mathbf{D}$，定义函子 $F : \mathbf{C}\to\mathbf{D}$ 满足：

- 对于 $\mathbf{C}$ 中的任意对象 $A$，在 $\mathbf{D}$ 中都有对象 $F(A)$
- 对于 $\mathbf{C}$ 中的任意态射 $f : A\to B$，在 $\mathbf{D}$ 中都有态射 $F(f) : F(A)\to F(B)$

???+ example "例"

    遗忘函子（forgetful functor）$U : \mathbf{Grp}\to\mathbf{Set}$，将一个群映射到一个集合中，将群同态映射到集合间的函数

    幂集函子（power set functor）$P : \mathbf{Set}\to\mathbf{Set}$，将一个集合映射到它的幂集，将原集合中的函数 $f : A\to B$ 映射到函数 $P(f) : \mathcal{P}(A)\to\mathcal{P}(B)$，即从 $U\subseteq A$ 到值域 $f(U)\subseteq B$ 的映射

    自函子（endofunctor）$1_{\mathbf{C}} : \mathbf{C}\to\mathbf{C}$，将一个范畴映射到它本身

#### 函子公理
函子 $F : \mathbf{C}\to\mathbf{D}$ 也需要满足两个公理：

1. 对于任意对象 $X\in\mathbf{C}$，恒有 $F(\mathrm{id}_X)=\mathrm{id}_{F(X)}$
2. 对于态射 $f : Y\to Z$、$g : X\to Y$，恒有 $F(f\circ g) = F(f)\circ F(g)$

#### $\mathbf{Hask}$ 范畴上的函子
Haskell 中的 Functor 定义是：
```haskell 
class Functor (f :: * -> *) where 
    fmap :: (a -> b) -> f a -> f b
```
对于 Haskell 中的 Functor，它实际上是从 $\mathbf{Hask}$ 范畴（types）到它子范畴的变换。比如列表函子 $\texttt{[]} : \mathbf{Hask}\to\mathbf{Lst}$（其中 $\mathbf{Lst}$ 是所有 Haskell 中列表类型构成的范畴）

它也达成了范畴论中对于函子的要求。函子需要进行两个操作：将一个范畴中的对象映射到另一个范畴中、将一个范畴中的态射映射到另一个范畴中。以 Maybe 为例，它实现了函子的要求：

1. Maybe 是一个类型构造器，他可以将任意类型 T 变成新类型 Maybe T，相当于从 $\mathbf{Hask}$ 范畴的对象变成了 $\mathbf{Maybe}$ 范畴的对象 
2. fmap 函数接收一个 a -> b 类型的函数，返回一个 Maybe a -> Maybe b 类型的函数，相当于将 $\mathbf{Hask}$ 范畴中的态射 $f : A\to B$ 映射成了 $\mathbf{Maybe}$ 范畴中的态射 $\mathbf{Maybe}(f) : \mathbf{Maybe}(A)\to\mathbf{Maybe}(B)$

!!! warning "注意"
    时刻记住这里研究的是 $\mathbf{Hask}$ 范畴和它的子范畴，对象是类型而不是值，态射是函数也指的是从类型到类型

同时，Haskell 中的 Functor 也满足函子公理：

1. fmap id = id 即 fmap (id :: A -> A) = (id :: f A -> f A)
2. fmap (f . g) = fmap f . fmap g

### 单子（Monads）
> 一个单子说白了不过就是自函子范畴上的一个幺半群而已 \_(:з」∠)\_

自函子在前面说到过是从一个范畴到自身的一个函子，如范畴 $\mathbf{C}$ 上的自函子是 $F : \mathbf{C}\to\mathbf{C}$。自函子范畴就是对象都是自函子的范畴。幺半群和 Haskell 中学到的 Monoid 类型类一样，是一个有可结合二元运算和单位元的代数结构。因此单子就是一个自函子，而且它有可结合二元运算（Haskell 中 `>=>`）和单位元（Haskell 中 `return`）。

一个单子 $M : \mathbf{C}\to\mathbf{C}$ 还包含两个态射（对于范畴 $\mathbf{C}$ 中的所有对象 $X$）：

1. $\mathrm{unit}_X^M : X\to M(X)$
2. $\mathrm{join}_X^M : M(M(X))\to M(X)$

（当式子中的单子明显是 $M$ 时，可以省略上标 ${}^M$）

Haskell 中 Monad 的定义是：
```haskell 
class Functor m => Monad m where 
    return :: a -> m a 
    (>>=)  :: m a -> (a -> m b) -> m b
```
其中很显然多态函数 `return` 对应了定义中的 $\mathrm{unit}$，但是 `>>=` 和 $\mathrm{join}$ 的对应关系并不明显。因此 Haskell 中有一个工具函数 `join`，它的效果就是定义中的 $\mathrm{join}$，而且它可以和 `>>=` 互相定义：
```haskell 
join :: Monad m => m (m a) -> m a
join x = x >>= id

(>>=) :: m a -> (a -> m b) -> m b 
x >>= f = join $ fmap f x
```
所以 Haskell 中为 Monad 要求定义 `>>=` 就相当于定义了 $\mathrm{join}$

例如，幂集函子 $P : \mathbf{Set}\to\mathbf{Set}$ 也是一个单子，可以为它定义 $\mathrm{unit}$ 和 $\mathrm{join}$ 两个态射。Haskell 中的列表也可以近似看作幂集函子。

???+ abstract "态射/函数的类型"

    |幂集函子|Haskell 中列表|
    |:-:|:-:|
    |一个集合 $S$ 和一个态射 $f : A\to B$|一个类型 T 和一个函数 f :: A -> B|
    |$P(f) : \mathcal{P}(A)\to\mathcal{P}(B)$|fmap f :: [A] -> [B]|
    |$\mathrm{unit}_S : S\to\mathcal{P}(S)$|return :: T -> [T]|
    |$\mathrm{join}_S : \mathcal{P}(\mathcal{P}(S))\to\mathcal{P}(S)$|join :: [[T]] -> [T]|

???+ abstract "态射/函数的定义"

    |幂集函子|Haskell 中列表|
    |:-:|:-:|
    |$(\mathcal{P}(f))(S) = \\{f(a):a\in S\\}$|fmap f xs = [ f a \| a <- xs ]|
    |$\mathrm{unit}_S(x) = \\{x\\}$|return x = [x]|
    |$\mathrm{join}_S(L) = \bigcup L$|join xs = concat xs|

#### 单子公理
给定一个单子 $M : \mathbf{C}\to\mathbf{C}$，和一个态射 $f : A\to B$（其中 $A,B\in \mathbf{C}$），那么满足下面四条定律：

1. $\mathrm{join}\circ M(\mathrm{join})=\mathrm{join}\circ\mathrm{join}$
2. $\mathrm{join}\circ M(\mathrm{unit})=\mathrm{join}\circ\mathrm{unit}=\mathrm{id}$
3. $\mathrm{unit}\circ f = M(f)\circ\mathrm{unit}$
4. $\mathrm{join}\circ M(M(f)) = M(f)\circ\mathrm{join}$

也可以很自然地将其转化为 Haskell 中的表述：

1. join . fmap join = join . join 
2. join . fmap return = join . return = id 
3. return . f = fmap f . return 
4. join . fmap (fmap f) = fmap f . join

在 Haskell 中，使用 `>>=` 也有三个定律和这四个定律是等价的：

1. return x >>= f = f x 
  ```haskell 
    return x >>= f 
  = join (fmap f (return x)) = join (fmap f . return $ x)
  = join (return (f x)) = join (return . f $ x)
  = join . return $ (f x)
  = id (f x)
  = f x
  ```
2. m >>= return = m
  ```haskell 
    m >>= return 
  = join (fmap return m) = join . fmap return $ m 
  = id m
  = m 
  ```
3. (m >>= f) >>= g = m >>= (\x -> f x >>= g)
  ```haskell 
    (m >>= f) >>= g 
  = (join (fmap f m)) >>= g = join (fmap g (join (fmap f m)))
  = join . fmap g . join $ fmap f m 
  = join . join . fmap (fmap g) $ fmap f m 
  = join . join . fmap (fmap g) . fmap f $ m 
  = join . join . fmap (fmap g . f) $ m 
  = join . fmap join . fmap (fmap g . f) $ m 
  = join . fmap (join . (fmap g . f)) $ m 
  = join . fmap (\x -> join (fmap g (f x))) $ m 
  = join . fmap (\x -> f x >>= g) $ m 
  = join (fmap (\x -> f x >>= g) m)
  = m >>= (\x -> f x >>= g)
  ```

有关 do 语句和 `>=>` 的公理表述在上文中已经说过

---

## 后记
啃了将近一个月，算是把 Haskell 的主要内容都啃完了。主要就是前期看 [Learn You a Haskell](http://learnyouahaskell.com/chapters)，后期看 [Typeclassopedia](https://wiki.haskell.org/Typeclassopedia)，都是 pdcxs 推荐给的教程。但是一堆视频一个都没有耐心看进去qwq

后面的部分的理解感觉也没到位，Category、Arrow 等这些类型类也就是大致地看了一眼，甚至有什么用都不太清楚\_(:з」∠)\_

感觉 Haskell 这门语言确实很神奇，很多语法都很有意思，而且可以做到非常贴近数学、贴近数学概念。学的时候也是越学坑越多，先是函数式编程引申到了 lambda 演算，然后是函子等一系列概念引申到了范畴论，目前范畴论简单地看了一部分，lambda 演算也没深入研究，以后有时间再说了（咕咕咕）

现在感觉我学到的 Haskell 简直是皮毛，还有一堆源码里的东西不知道是怎么回事（包括但不限于#，~），也还有一堆类型类和用法没有学到（包括但不限于 Monad Transformer、Writer、Reader、State、Comonad、MonadFix、Lens、Parsec、……）~~md，这么一看差的还真多~~，以后有时间再慢慢学了，这个假期还有好多其它事要干呢，Haskell 这边先摸了_(:з」∠)_


## Reference
- [Learn You a Haskell](http://learnyouahaskell.com/chapters)
- [Writing foldl using foldr - StackOverflow](https://stackoverflow.com/questions/6172004/writing-foldl-using-foldr)
- [Haskell：用foldr定义foldl](https://blog.csdn.net/WinterShiver/article/details/103308165)
- [Typeclassopedia - Haskell wiki](https://wiki.haskell.org/Typeclassopedia)
- [Hoogle](https://hoogle.haskell.org/)
- [Functors, Applicatives, And Monads In Pictures](https://adit.io/posts/2013-04-17-functors,_applicatives,_and_monads_in_pictures.html)
- [Haskell学习 - functor](http://02s949.coding-pages.com/2018/08/15/haskellc/)
- [Haskell语言学习笔记（8）Monoid - zwvista](https://blog.csdn.net/zwvista/article/details/54863519)
- [Haskell语言学习笔记（16）Alternative - zwvista](https://blog.csdn.net/zwvista/article/details/62238541)
- [Haskell语言学习笔记（40）Arrow（1） - zwvista](https://blog.csdn.net/zwvista/article/details/78679542)
- [24 Days of GHC Extensions: Arrows - Tom Ellis](https://ocharles.org.uk/blog/guest-posts/2014-12-21-arrows.html)
- [Haskell语言学习笔记（47）Arrow（2） - zwvista](https://blog.csdn.net/zwvista/article/details/78690485)
- [Haskell/Category theory - wikibooks](https://en.wikibooks.org/wiki/Haskell/Category_theory)
- [Category theory - wikipedia](https://en.wikipedia.org/wiki/Category_theory)
- [范畴论 - 维基百科](https://zh.wikipedia.org/wiki/%E8%8C%83%E7%95%B4%E8%AE%BA)
- [Monad (category theory) - wikipedia](https://en.wikipedia.org/wiki/Monad_(category_theory))
- [Functor - wikipedia](https://en.wikipedia.org/wiki/Functor)

<p style="text-align: center; font-size: x-large; font-weight: bolder"> "The End?" </p>