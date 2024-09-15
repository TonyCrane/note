---
counter: True
comment: True
---

# Network Security Lab 1

!!! abstract
    网络安全 lab1 实验报告

    !!! warning "仅供学习参考，请勿抄袭"

## Goal

> Lab 01 aims to practice commonly used tools for packet sniffing, packet crafting, and port scanning.
>
> For packet sniffing and packet crafting, we use basic web exploitation CTF challenges for example. Solving these challenges helps to understand the HTTP protocol and technologies involved in information transfer and display over the internet like PHP, CMS's (e.g., Django), SQL, Javascript, and more.

## Tasks
### Task 1: http://10.15.111.100/game1
#### Level 1.

Press `F12` to toggle the developer tools of Chrome, we can find the comment with password and the real check process in the source code:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/1-1.png" width="80%" style="margin: 0 auto;">
</div>

Input `029c64152b6954e91d39183f8d2e07a9` then we can enter the next level.

#### Level 2.

This page just add a script to detect openning of context menu. So `F12` still works:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/1-2.png" width="80%" style="margin: 0 auto;">
</div>

Input `b910592a8ff0f56123105740c1735eb0` to enter the next level.

#### Level 3.

We can't find flag in the source code of this level. Then try to curl it with verbose mode:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/1-3.png" width="80%" style="margin: 0 auto;">
</div>

We can find the flag in the response header.

### Task 2: http://10.15.111.100/game2
#### Level 1.

With the comment in the page source, we can notice that there has a 302 redirection. Then we curl it with verbose mode:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/2-1.png" width="80%" style="margin: 0 auto;">
</div>

#### Level 2.

Note that we need to make us looks like referer from `http://localhost/`. We can set the referer field in the request header. A method to do this is to use curl with `--referer` option:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/2-2.png" width="80%" style="margin: 0 auto;">
</div>

And then we can find the password in the html code of response:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/2-3.png" width="80%" style="margin: 0 auto;">
</div>

#### Level 3.

In the comment of the page source, it tells us that this level works with a cookie. In the "Application" part of develop tools, we can find that there is a cookie `admin: 0`. So we can change it to 1 in the develop tools and refresh the page:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/2-4.png" width="80%" style="margin: 0 auto;">
</div>

Also, we can use curl to set cookie:

```text
❯ curl -v http://10.15.111.100/game2/f451899344a962d6d27a73e2902f8e51.php --cookie "admin=1"
*   Trying 10.15.111.100:80...
* Connected to 10.15.111.100 (10.15.111.100) port 80 (#0)
> GET /game2/f451899344a962d6d27a73e2902f8e51.php HTTP/1.1
> Host: 10.15.111.100
> User-Agent: curl/7.71.1
> Accept: */*
> Cookie: admin=1
>

...

Flag 只有来自 admin 才看得到。
Ok, give you flag: ACTF{47ca8aa874ba92a43621d5ff8cde0cdf}<!--Do you know how http cookie worked? -->
...
```

### Task 3: http://10.214.160.13:10000/
#### Level 1.

The comment hint that there is a `1.php.bak` still exists. So we can access and download it. Then we can find the entry of the next level:

```html
<a href="the2nd.php">进入第二关</a>
```

#### Level 2 & 3.

In the second level, there is a button, whatever you submit, it always redirect to `3rd.php` which ask you "where are you from" and then redirect back to `the2nd.php`:

```text
❯ curl -X POST -d "text=" http://10.214.160.13:10000/the2nd.php
...
    jumping...
    <script>
        function jump(url){
            document.body.appendChild(document.createElement('iframe')).src='javascript:"<script>top.location.replace(\''+url+'\')<\/script>"';
        }
        setInterval("jump('3rd.php')",2000);
...
❯ curl http://10.214.160.13:10000/3rd.php
<script>alert('你从哪里来？');window.location='the2nd.php';</script>
```

With the same idea of task 2 level 2, we can set the referer field to `http://10.214.160.13:10000/the2nd.php` to "answer" the "question":

```text
❯ curl --referer http://10.214.160.13:10000/the2nd.php -v http://10.214.160.13:10000/3rd.php
*   Trying 10.214.160.13:10000...
* Connected to 10.214.160.13 (10.214.160.13) port 10000 (#0)
> GET /3rd.php HTTP/1.1
> Host: 10.214.160.13:10000
> User-Agent: curl/7.71.1
> Accept: */*
> Referer: http://10.214.160.13:10000/the2nd.php
>
...
<button type="button" onclick="javascript:location.href='di4guan.php'">你又要到哪里去</button>
...
```

#### Level 4.

No any information in the page source. Then try to curl and get the response header:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab1/3-1.png" width="80%" style="margin: 0 auto;">
</div>

We can find `Next: wozaizheli.php`

#### Level 5.

Through the page source, we can find the form details:

```html
<script>
function joy(){
    document.getElementById("joy").style.display="none";
}
</script>
点击按钮就能拿到flag啦~<br>
<div id="joy" onmouseover="joy()">
<form method="post">
<input type="hidden" value="HIT" name="HIT"/>
<input type="submit" value="点我" style="display:block" id="submit" name="submit"/>
</div>
</body>
```

So normally we can't press the button because it will disappear when we move the mouse to it. We can use curl to submit the form:

```text
❯ curl -X POST -d "HIT=HIT" http://10.214.160.13:10000/wozaizheli.php
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <meta http-equiv="Content-Language" content="zh-CN" />
</head>
<body>
<div align="center">
<script>
function joy(){
    document.getElementById("joy").style.display="none";
}
</script>
点击按钮就能拿到flag啦~<br>
<div id="joy" onmouseover="joy()">
<form method="post">
<input type="hidden" value="HIT" name="HIT"/>
<input type="submit" value="点我" style="display:block" id="submit" name="submit"/>
</div>
flag:  AAA{y0u_2a_g0od_front-end_Web_developer}</body>
</html>
```

Then we find the flag: `AAA{y0u_2a_g0od_front-end_Web_developer}`.