---
hide:
    - date
home: true
template: home.html
statistics: true
---

# o(〃'▽'〃)o Hi!

这里是鹤翔万里（TonyCrane）的个人笔记本哦！  

<!-- [:octicons-info-16: 关于我](about/) /  -->
[:material-clock-time-two-outline: 最近更新](changelog/) / 
[:octicons-link-16: 朋友们!](links/) / 
[:material-chart-line: 站点统计](javascript:toggle_statistics();)

<div id="statistics" markdown="1" class="card" style="width: 27em; border-color: transparent; opacity: 0; font-size: 75%">
<div style="padding-left: 1em;" markdown="1">
页面总数：{{pages}}  
总字数：{{words}}  
代码块行数：{{codes}}  
网站运行时间：<span id="web-time"></span>
</div>
</div>

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
function toggle_statistics() {
    var statistics = document.getElementById("statistics");
    if (statistics.style.opacity == 0) {
        statistics.style.opacity = 1;
    } else {
        statistics.style.opacity = 0;
    }
}
</script>