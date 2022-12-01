---
comment: True
---

# ByteCTF 2021 Final Writeup

!!! abstract
    这场比赛 misc AK 了，还挺爽的

---

## Enrich Life
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

首先使用 ffprobe 发现 description 里的 hint：`FlagInChromaFrames`，以及颜色格式为 yuv240p，所以思路就是看一看 yuv 中代表色度 chroma 的 uv 分量

通过和抖音上的源视频对比发现题目视频的前半段有比较明显的浅红色（v）闪烁，并且经过 [YuvEye](http://www.realrace.cn/YUVEye.html) 打开观察，发现 v 通道各个帧之间有明显的明暗变化，持续到 1160 帧左右恢复正常

合理猜测 v 分量中利用相对的明/暗代表01以某种方式藏了信息

根据 hint：Plot the data you found over time and find the pattern，把每一帧的 v 分量的平均值随时间的变化画出散点图：

```python
import cv2
import numpy as np
import matplotlib.pyplot as plt

video = cv2.VideoCapture('enrich_life.mp4')

n = 300
x = [i for i in range(n*8)]
y = []
for i in range(n*8):
    _, frame = video.read()
    frame = frame[:, :, :]
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2YUV)
    Y, U, V = cv2.split(frame)
    y.append(np.abs(np.average(V)))
    
plt.figure(figsize=(64,16))
plt.scatter(x, y, s=1)
plt.show()

print(y)
```

![](/assets/images/writeups/bytectf2021_final/Untitled.png)

发现前期的 v 分量呈现出 5 个一组的上升/下降，所以把上升的一组记为 1，下降的一组记为 0，转换得到 flag：

```python
import cv2
import numpy as np
from Crypto.Util.number import *
video = cv2.VideoCapture('enrich_life.mp4')
y = np.reshape([np.abs(np.average(cv2.split(cv2.cvtColor(video.read()[1][:,:,:], cv2.COLOR_BGR2YUV))[2])) for _ in range(150*8)], (240,5))
print(long_to_bytes(int("".join(['1' if y[i, 0] < y[i, 1] else '0' for i in range(240)]), 2)))
# b'ByteCTF{bYTEctf-SecurityYYDS}\x8a'
```

## FPS_game
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

地面高度 1072851582，用 Cheat Engine 改成 1078000000 锁定

![](/assets/images/writeups/bytectf2021_final/Untitled%201.png)

另解：把 dll（用 il2cppdumper 辅助分析）中角色是否在地面的判定改为恒为真，这样在空中也能继续向上跳。

![](/assets/images/writeups/bytectf2021_final/%E5%9B%BE2.jpg)

## Lisa's cat
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

![](/assets/images/writeups/bytectf2021_final/Untitled%202.png)

用 RGB2YUV 转换图片

在 green 0 中看到下图

![](/assets/images/writeups/bytectf2021_final/Untitled%203.png)

然后获取 red 0 和 blue 0

![](/assets/images/writeups/bytectf2021_final/yuv_r.bmp)

![](/assets/images/writeups/bytectf2021_final/yuv_b.bmp)

感觉很像，异或一下得到下图

![](/assets/images/writeups/bytectf2021_final/233.bmp)

根据 hint，猜测是使用 Arnold's Cat Map 进行变换，再根据 green 0 中的数字取 Cat Map 参数

```python
import os

from PIL.Image import open as load_pic, new as new_pic

def main(path, iterations, name="arnold_cat-{name}-{index}.png"):
    title = os.path.splitext(os.path.split(path)[1])[0]
    ppath=path
    counter = 0
    while counter < iterations:
        with load_pic(path) as image:
            dim = width, height = image.size
            with new_pic(image.mode, dim) as canvas:
                for x in range(width):
                    for y in range(height):
                        nx = (1 * x + 20 * y) % width
                        ny = (21 * x + 421 * y) % height
                        canvas.putpixel((nx, height-ny-1), image.getpixel((x, height-y-1)))
        counter += 1
        print(counter, end="\r")
        path = name.format(name=title, index=counter)
        canvas.save(path)

    return canvas

result = main("233.bmp", 384)
result.show()
```

第一张图就是

![](/assets/images/writeups/bytectf2021_final/arnold_cat-233-1.png)

## Undercover
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

拿到题目发现给题的方式不是发附件而是直接插入图片，所以考虑是不是和链接有关系：

```text
https://p3.toutiaoimg.com/img/tos-cn-i-qvj2lq49k0/7a19b5d53d014130ab3c00f73a8d4645~tplv-yykgsuqxec-imagexlite-0bb543cf5d800a1a226c9d1fe716be95.png
```

发现了 `~tplv-` ，所以上图应该是使用 velmageX 用处理模板处理过的，所以就直接删掉处理，得到原始图片的地址：

```text
https://p3.toutiaoimg.com/img/tos-cn-i-qvj2lq49k0/7a19b5d53d014130ab3c00f73a8d4645~tplv-yykgsuqxec-image.png
或
https://p3.toutiaoimg.com/img/tos-cn-i-qvj2lq49k0/7a19b5d53d014130ab3c00f73a8d4645~noop.png
```

再根据 hint：Original image have exif，查看这个图片的 exif，发现有 Author 一项：`Author: From: Zach Oakes`

搜索 Zach Oakes 发现他写的一个隐写工具：[https://sekao.net/pixeljihad/](https://sekao.net/pixeljihad/)

把这张图片传入拿到 flag：

![](/assets/images/writeups/bytectf2021_final/Untitled%204.png)