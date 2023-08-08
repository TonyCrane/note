---
comment: true
counter: true
---

# ffmpeg 套件使用杂记

!!! abstract
    在字幕压制/日常使用中的 ffmpeg 套件使用方法记录

## ffmpeg
### 一些压制参数
- `-i <input_video>` 输入文件
- `-b:a 320k` 压制音频比特率 320kbps

    ??? note "为什么要用 320kbps（来自 NetaP495L 私聊）"
        - https://hydrogenaud.io/index.php?topic=120062.0、https://hydrogenaud.io/index.php?topic=120166.0
        - ffmpeg 默认 AAC 编码器压 128k 的 AAC 的话会有明显音质损失（据说有观众能听出来）
        - 默认 AAC 编码器压 320k 要好一点
        - 或者根据 https://trac.ffmpeg.org/wiki/Encode/AAC 的指南编译一份包含 libfdk_aac 编码器的 ffmpeg 使用

- `-c:a copy` 拷贝音频流
- `-b:v 6000k` 指定视频比特率

### 压制字幕
ffmpeg 默认使用 libass 渲染字幕，用法就是添加一个 video filter：

- `-vf ass=<ass_filename>` 即可加载 ass 字幕文件并压到视频当中
- `-vf subtitles=<sub_filename>` subtitles 这个 filter 支持非 ass 格式的字幕（本质上是转为 ass 再给 libass 处理）
- `-vf ass=<ass_filename>:shaping=complex` 需要支持某些复杂字体特性时要这样
    - ass filter 可以通过 shaping 选定造形引擎
    - FriBidi 1.0.12 (SIMPLE) 只支持一小部分连字，不能处理任何 OpenType 特性
    - HarfBuzz-ng 7.3.0 (COMPLEX) 能正确处理多文种造形
    - （以上转自 NetaP495L 的回复）

### 合并图片流
Aegisub 在搞跟踪的时候需要导出时间范围内的视频切片，但我这里直接切视频不太好使（因为默认有 crf 参数，我目前的 ffmpeg 没配置这个），另一种方式是导出范围内的系列图片，这样是可以的，只是需要后续再用 ffmpeg 拼一下：

```shell
$ ffmpeg -r 23.976 -f image2 -i "...-%05d.jpg" -vcodec libx264 clip.mp4
```

## ffprobe
### 提取关键帧
Aegisub 可以载入关键帧文件显示在音频中，方便打轴时对关键帧。这个文件可以用 Aegisub 导出，也可以用 ffprobe 逐帧读取帧类型，筛选关键帧输出索引。需要注意的是一些源的关键帧分布并非在画面切换的位置，所以可以先用 ffmpeg 无参数压到 mp4（`ffmpeg -i <origin_video> output.mp4`），这样筛选出的关键帧一般就是画面切换的位置了。

```shell
$ ffprobe -i output.mp4 -select_streams v -show_frames -show_entries frame=pict_type -of csv | sed -n '3,$p' | grep -n I | cut -d ':' -f 1 > tmp.txt
```

- ffprobe 这句用来打印每一帧的帧类型，关键帧所在的行输出 "frame,I"
- `sed -n '3,$p'` 从第三行开始显示（第一行是第 0 帧，第二行是空行，不删掉后面的序号会整体移两个）
- `grep -n I` 筛选关键帧出现的位置
- `cut -d ':' -f 1` 仅保留 grep -n 输出的行号（也就是帧号）

Aegisub 加载之前需要在开头加上关键帧文件信息（以及刚才删掉的第 0 帧）：

```text
# keyframe format v1
fps 0
0
```

```shell
$ echo '# keyframe format v1\nfps 0\n0' | cat - tmp.txt > keyframes.txt
```