---
hide:
    - date
home: true
template: home.html
statistics: true
---

# o(〃'▽'〃)o Hi!

!!! info "site.info"
    这里是鹤翔万里（TonyCrane）的个人笔记本哦！  

    网站组织结构大概是安全方向的在 [Security](sec/) 部分，网络相关的在 [Web](web/) 部分，打 CTF 学到用到的在 [CTF](ctf/) 部分（部分比赛的 writeup 会放在 [Writeups](writeups/) 部分），其它计算机相关的在 [Computer Science](cs/) 部分，剩下的丢在 [Others](others) 里面。

    如果发现了有内容错误可以通过文末评论告诉我吗qwq

    大概是随时更新，~~随时咕咕咕~~

    ??? question "about(site.author)"
        18 岁，事浙江大学信息安全专业大二学生，事哔哩哔哩 up 主 [@鹤翔万里](https://space.bilibili.com/171431343)，事 AAA 战队 misc 手 @TonyCrane 

        - 主页：https://tonycrane.cc/
        - 博客：https://blog.tonycrane.cc/
        - GitHub：https://github.com/TonyCrane/
    
    ??? info "site.statistics"
        页面总数：{{pages}}  
        总字数：{{words}}  
        代码块行数：{{codes}}  
        网站运行时间：<span id="web-time"></span>

```python title="script.py"
if visitor.name == 'TonyCrane':
    print(f"看什么看，快去学习/做视频/写笔记/打CTF/{'/'.join(tasks)}\n")
    logging.warning("别摸了")
else:
    print("希望这个小破站点能对你有所帮助ヽ(*´∀｀)八(´∀｀*)ノ\n")
    thanks_list.append(visitor.name)
```

<script>
function updateTime() {
    var date = new Date();
    var now = date.getTime();
    var startDate = new Date("2022/01/03 09:10:00");
    var start = startDate.getTime();
    var diff = now - start;
    var y, d, h, m;
    y = Math.floor(diff / (365 * 24 * 3600 * 1000));
    diff -= y * 365 * 24 * 3600 * 1000;
    d = Math.floor(diff / (24 * 3600 * 1000));
    h = Math.floor(diff / (3600 * 1000) % 24);
    m = Math.floor(diff / (60 * 1000) % 60);
    if (y == 0) {
        document.getElementById("web-time").innerHTML = d + "<span class=\"heti-spacing\"> </span>天<span class=\"heti-spacing\"> </span>" + h + "<span class=\"heti-spacing\"> </span>小时<span class=\"heti-spacing\"> </span>" + m + "<span class=\"heti-spacing\"> </span>分钟";
    } else {
        document.getElementById("web-time").innerHTML = y + "<span class=\"heti-spacing\"> </span>年<span class=\"heti-spacing\"> </span>" + d + "<span class=\"heti-spacing\"> </span>天<span class=\"heti-spacing\"> </span>" + h + "<span class=\"heti-spacing\"> </span>小时<span class=\"heti-spacing\"> </span>" + m + "<span class=\"heti-spacing\"> </span>分钟";
    }
    setTimeout(updateTime, 1000 * 60);
}
updateTime();
</script>