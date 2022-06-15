---
counter: True
comment: True
---

# 图片隐写

## 隐藏文件
图片一般只读取到需要的大小就停止，所以可以在其二进制文件的后面插入其他文件

这时直接使用 binwalk foremost 等工具就可以发现、提取

## png 改变大小
png 的文件头记录了图片的大小，超过大小的数据将不会出现在图片里<br/>
如果是利用这个方式进行隐写的可以直接更改 png 文件的十六进制数据来改变大小看到隐藏的内容

### png 文件头格式
- （ 8 bytes）png 文件头标识：`89 50 4E 47 0D 0A 1A 0A`
- （ 4 bytes）IHDR 数据块长度 13: `00 00 00 0D`
- （ 4 bytes）IHDR 块标识：`49 48 44 52`
- （13 bytes）IHDR 块：
    - （4 bytes）宽度，以像素为单位，大端序
    - （4 bytes）高度，以像素为单位，大端序
    - （5 bytes）bit depth、color type、compression method、filter method、interlace method
- （ 4 bytes）crc 校验码，从 IHDR 标识到块结束总共 17 bytes 的 crc 校验码 

### 爆破大小
```python
import struct
import binascii

img = open("....png", "rb").read()
height, width = 0, 0
for i in range(...):
    for j in range(...):
        data = img[12:16] + struct.pack('>i', i) + struct.pack('>i', j) + img[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if crc32 == 0x........:
            height = i
            width = j
            print('hex:', hex(i), hex(j))
            
new_img = list(img)
new_img[16:20] = struct.pack('>i', height)
new_img[20:24] = struct.pack('>i', width)

with open('out.png','wb') as f:
    f.write(bytes(new_img))
```

## LSB 隐写
LSB（Least Significant Bit）是一种常见的隐写方法。因为人眼对颜色的分辨有限度，所以可以更改图片的每个像素点的颜色比特的最低位来隐藏信息，但不被人眼分辨出来

这种题目一般可以使用 stegsolve 软件来完成，有两种情况：

- 最低位提取出来作为灰度是一张图片：直接在 stegsolve 中打开然后右箭头翻找就可以
- 最低位隐藏了二进制信息：stegsolve 打开，Analyze -> Data Extract

针对第一种情况，也可以利用 `PIL` 库来完成：
```python 
from PIL import Image 

img = Image.open("...")
width, height = img.size
img2 = Image.new("L", img.size)

for i in range(width):
    for j in range(height):
				R, G, B, A = pix = img.getpixel((i, j))
        # C, M, Y, K = pix = img.getpixel((i,j))
        # Y, Cb, Cr = pix = img.getpixel((i, j))
        if R & 0b1 == 0:
            img2.putpixel((i,j),0)
        else:
            img2.putpixel((i,j),255)	

img2.show()
```

在 mac 上，stegsolve data extract 会出现 UI 问题，可以使用命令行工具 zsteg 替代：
```shell 
zsteg image.png b1,lsb -a -v    # 显示所有 bgr 顺序下的最低位 lsb
zsteg -E '1b,bgr,lsb' image.png # 确定 bgr 顺序后提取十六进制值
```

### 色彩模式
但有时原文件的 lsb 看不到或者不清楚，考虑是转换了色彩格式

因为 lsb 的原理是提取视觉影响弱的低位，所以要求转换必须完全精准，一般都采用 `PIL` 或者 `cv2` 库中的内置方法转换（因为运算方法确定），而不使用 Ps 等软件来转换色彩模式（过于复杂，不易操控，会损失低位数据）

`PIL.Image` 中支持 11 种图片模式：1、L、P、RGB、RGBA、CMYK、YCbCr、LAB、HSV、I、F<br/>
[https://pillow.readthedocs.io/en/stable/handbook/concepts.html#concept-modes](https://pillow.readthedocs.io/en/stable/handbook/concepts.html#concept-modes)

- `1` 黑白二值（但是是0和255）
- `L` 灰度（I也是灰度，但L是8bit存储，I是32bit存储
    - `RGB`转`L`：`L = R * 299/1000 + G * 587/1000+ B * 114/1000`
- `P` 8bit色值

RGB和CMYK转换时有色差，因为转换的公式是：
```python
C = 255 - R
M = 255 - G
Y = 255 - B
K = 0
```
也因此在LSB隐写时这两种模式没有差别

但是 RGB 和 YCbCr、LAB、HSV 之间复杂的转换时就有了差别，使用时直接 `.convert("mode")` 即可。一些 PIL 不支持的转换也可以使用 cv2

## Arnold's cat map
Arnold's cat map 是一种算法，来打乱像素点，并且在一定次数后会恢复原样<br/>
https://en.wikipedia.org/wiki/Arnold%27s_cat_map
```python 
import os
from PIL.Image import open as load_pic, new as new_pic

def main(path, iterations, keep_all=False, name="arnold_cat-{name}-{index}.png"):
    title = os.path.splitext(os.path.split(path)[1])[0]
    ppath=path
    counter = 0
    while counter < iterations:
        with load_pic(path) as image:
            dim = width, height = image.size
            with new_pic(image.mode, dim) as canvas:
                for x in range(width):
                    for y in range(height):
                        nx = (2 * x + 1 * y) % width   # <- 这里参数可以调
                        ny = (1 * x + 1 * y) % height  # <- 这里参数可以调
                        canvas.putpixel((nx, height-ny-1), image.getpixel((x, height-y-1)))
        if counter > 0 and not keep_all:
            os.remove(path)
        counter += 1
        print(counter, end="\r")
        path = name.format(name=title, index=counter)
        canvas.save(path)
    return canvas

result = main("...", ...)
result.show()
```

## 隐写工具
有些图片隐写是利用某些软件来隐藏的数据，这种一般都需要密码来解密，常见的有：

- steghide：http://steghide.sourceforge.net/
- SilentEye：https://achorein.github.io/silenteye/