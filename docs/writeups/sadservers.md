---
comment: True
counter: True
---

# SadServers Writeup

!!! abstract
    水 tg 发现的，挺好玩的，就做一做，学到很多，就写一写。
    
    平台地址在 https://sadservers.com/ 。大概类似运维？反正大概就是修复一些 Linux 服务器出现的问题。

    不算 CTF，不知道咋分类，就扔这里吧

    看起来题目不多，据说是 "new challenges weekly"，出的话或许可以随时更新？（咕咕咕

---

## "Saint John"

> **Scenario:** "Saint John": what is writing to this log file?
> 
> **Level:** Easy
> 
> **Description:** A developer created a testing program that is continuously writing to a log file /var/log/bad.log and filling up disk. You can check for example with `tail -f /var/log/bad.log`.
This program is no longer needed. Find it and terminate it.
> 
> **OS:** Ubuntu 22.04 LTS

可以 tail -f /var/log/bad.log 看一眼确实在一直填东西。然后当然是先查一下后台进程 ps -aux，可以发现有一条很可疑：
```text
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
ubuntu       610  0.0  1.7  17672  8212 ?        S    07:57   0:00 /usr/bin/python3 /home/ubuntu/badlog.py
...
```
可以 cat 看一下 badlog.py:
```python
#! /usr/bin/python3
# test python writing to a file

import random
import time
from datetime import datetime

f = open('/var/log/bad.log', 'a')
while True:
  r = random.randrange(2147483647)
  f.write(str(datetime.now()) + ' token: ' + str(r) + '\n')
  f.flush()
  time.sleep(1)
```
确实是在每一秒写一行。所以直接 kill -9 610 强制杀死这个进程就好了。

题目的本意大概是用 lsof 来查看使用某一文件的进程：
```text
ubuntu@ip-172-31-32-108:/$ lsof /var/log/bad.log 
COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF  NODE NAME
badlog.py 610 ubuntu    3w   REG  259,1    31275 67701 /var/log/bad.log
```

然后同样是强杀。

---

## "Saskatoon"

> **Scenario:** "Saskatoon": counting IPs.
> 
> **Level:** Easy
> 
> **Description:** There's a web server access log file at /home/admin/access.log. The file consists of one line per HTTP request, with the requester's IP address at the beginning of each line.
> 
> Find what's the IP address that has the most requests in this file (there's no tie; the IP is unique). Write the solution into a file /home/admin/highestip.txt. For example, if your solution is "1.2.3.4", you can do echo "1.2.3.4" > /home/admin/highestip.txt
> 
> **OS:** Debian 11

所有需要的东西都在 access.log 里面，所以写一个 python 脚本读取、统计、排序、输出就好了：
```python
with open("/home/admin/access.log", "r") as f:
    contents = f.readlines()

ips = [line.split(" ")[0] for line in contents]
cnt = list(set([(ips.count(ip), ip) for ip in ips]))
print(sorted(cnt)[-1])
# (482, '66.249.73.135')
```
所以请求最多的 ip 就是 66.249.73.135。

当然题目的意思是通过 shell 命令直接来做。可以 cat 然后 cut 来取出 ip，然后 sort | uniq -c 来统计次数（要先 sort，uniq 只会统计相邻的重复行），之后在 sort 一下，最后一行就是要的了：
```text
$ cat /home/admin/access.log | cut -d ' ' -f 1 | sort | uniq -c | sort | tail -n 1
    482 66.249.73.135
```
用 awk 来处理也很方便，直接一行解决：
```shell
$ awk '{print $1}' /home/admin/access.log | sort | uniq -c | sort | tail -n 1 | awk '{print $2}' > /home/admin/highestip.txt
```

---

## "Tokyo"

> **Scenario:** "Tokyo": can't serve web file
> 
> **Level:** Medium
> 
> **Description:** There's a web server serving a file /var/www/html/index.html with content "hello sadserver" but when we try to check it locally with an HTTP client like curl 127.0.0.1:80, nothing is returned. This scenario is not about the particular web server configuration and you only need to have general knowledge about how web servers work.
> 
> **OS:** Ubuntu 22.04 LTS

ps -aux 可以发现这个 web server 服务是由 apache2 提供的：
```text
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
www-data     774  0.0  0.9 1211728 4304 ?        Sl   08:27   0:00 /usr/sbin/apache2 -k start
www-data     775  0.0  0.9 1211728 4304 ?        Sl   08:27   0:00 /usr/sbin/apache2 -k start
...
```
去 /etc/apache2 逛了一圈，确实没什么问题。

`curl -v 127.0.0.1:80`，发现根本就连不上。可能是防火墙的问题，看一下 iptables：
```text
# iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```
发现 INPUT 链把所有 tcp 包都 DROP 了。所以可以直接情况规则：
```text
# iptables -F
```
然后再 curl 发现返回 403 Forbidden。检查一下 /var/www/html/index.html 的权限：
```text
# ls -l /var/www/html/index.html
-rw------- 1 root root 16 Aug  1 00:40 /var/www/html/index.html
```
所以需要修改一下权限，让所有人可读：
```text
# chmod +r /var/www/html/index.html
```
然后再 curl 就可以了。

---

## "Manhattan"

> **Scenario:** "Manhattan": can't write data into database.
> 
> **Level:** Medium
> 
> **Description:** Your objective is to be able to insert a row in an existing Postgres database. The issue is not specific to Postgres and you don't need to know details about it (although it may help).
> 
> Helpful Postgres information: it's a service that listens to a port (:5432) and writes to disk in a data directory, the location of which is defined in the data_directory parameter of the configuration file /etc/postgresql/14/main/postgresql.conf. In our case Postgres is managed by systemd as a unit with name postgresql.
> 
> **OS:** Debian 10

有一些难度，看了些提示。

首先 `systemctl status postgresql` 可以看出 postgresql 确实在运行，但是连不上。看一看 /var/log/syslog 没有什么异样。

试着 `systemctl restart postgresql` 重启 postgresql，没有报错，但是 /var/log/syslog 里面可以看到错误：
```text
Nov  3 09:11:58 ip-172-31-47-134 postgresql@14-main[884]: 2022-11-03 09:11:58.882 UTC [889] FATAL:  could not create lock file "postmaster.pid": No space left on device
```
No space left on device，所以 df 看一下磁盘用量：
```text
root@ip-172-31-47-134:/# df
Filesystem      1K-blocks    Used Available Use% Mounted on
udev               229200       0    229200   0% /dev
tmpfs               47660    1520     46140   4% /run
/dev/nvme1n1p1    8026128 1233676   6363196  17% /
tmpfs              238300       0    238300   0% /dev/shm
tmpfs                5120       0      5120   0% /run/lock
tmpfs              238300       0    238300   0% /sys/fs/cgroup
/dev/nvme1n1p15    126710     278    126432   1% /boot/efi
/dev/nvme0n1      8378368 8378340        28 100% /opt/pgdata
```
可以看到挂载在 /opt/pgdata 上的设备容量满了。检查一下这个目录：
```text
root@ip-172-31-47-134:/# ls -l /opt/pgdata
total 8285620
-rw-r--r--  1 root     root             69 May 21 22:20 deleteme
-rw-r--r--  1 root     root     7516192768 May 21 22:06 file1.bk
-rw-r--r--  1 root     root      967774208 May 21 22:17 file2.bk
-rw-r--r--  1 root     root         499712 May 21 22:23 file3.bk
drwx------ 19 postgres postgres       4096 May 21 22:24 main
```
可以发现一堆 .bk 备份文件占满了磁盘，删除、重启、测试，发现一切正常了：
```text
root@ip-172-31-47-134:/# rm /opt/pgdata/file*.bk
root@ip-172-31-47-134:/# ls -l /opt/pgdata
total 8
-rw-r--r--  1 root     root       69 May 21 22:20 deleteme
drwx------ 19 postgres postgres 4096 May 21 22:24 main
root@ip-172-31-47-134:/# systemctl restart postgresql
root@ip-172-31-47-134:/# sudo -u postgres psql -c "insert into persons(name) values ('jane smith');" -d dt
INSERT 0 1
```

---

## "Cape Town"

> **Scenario:** "Cape Town": Borked Nginx
> 
> **Level:** Medium
> 
> **Description:** There's an Nginx web server installed and managed by systemd. Running curl -I 127.0.0.1:80 returns curl: (7) Failed to connect to localhost port 80: Connection refused , fix it so when you curl you get the default Nginx page.
> 
> **OS:** Debian 11

首先 systemctl status nginx 检查一下 nginx 运行状态：
```text
$ sudo systemctl status nginx
● nginx.service - The NGINX HTTP and reverse proxy server
     Loaded: loaded (/etc/systemd/system/nginx.service; enabled; vendor preset: enabled)
     Active: failed (Result: exit-code) since Thu 2022-11-03 09:30:47 UTC; 42s ago
    Process: 584 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=1/FAILURE)
        CPU: 28ms

Nov 03 09:30:47 ip-172-31-33-45 systemd[1]: Starting The NGINX HTTP and reverse proxy server...
Nov 03 09:30:47 ip-172-31-33-45 nginx[584]: nginx: [emerg] unexpected ";" in /etc/nginx/sites-enabled/default:1
Nov 03 09:30:47 ip-172-31-33-45 nginx[584]: nginx: configuration file /etc/nginx/nginx.conf test failed
Nov 03 09:30:47 ip-172-31-33-45 systemd[1]: nginx.service: Control process exited, code=exited, status=1/FAILURE
Nov 03 09:30:47 ip-172-31-33-45 systemd[1]: nginx.service: Failed with result 'exit-code'.
Nov 03 09:30:47 ip-172-31-33-45 systemd[1]: Failed to start The NGINX HTTP and reverse proxy server.
```
发现有报错，说在 /etc/nginx/sites-enabled/default:1 有一个 unexpected ";"，所以去删掉它，然后重启。
```text
admin@ip-172-31-33-45:/$ sudo vim /etc/nginx/sites-enabled/default 
admin@ip-172-31-33-45:/$ sudo systemctl restart nginx
admin@ip-172-31-33-45:/$ sudo systemctl status nginx
● nginx.service - The NGINX HTTP and reverse proxy server
     Loaded: loaded (/etc/systemd/system/nginx.service; enabled; vendor preset: enabled)
     Active: active (running) since Thu 2022-11-03 09:32:32 UTC; 6s ago
    Process: 868 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
    Process: 869 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
   Main PID: 870 (nginx)
      Tasks: 2 (limit: 524)
     Memory: 2.4M
        CPU: 27ms
     CGroup: /system.slice/nginx.service
             ├─870 nginx: master process /usr/sbin/nginx
             └─871 nginx: worker process

Nov 03 09:32:32 ip-172-31-33-45 systemd[1]: Starting The NGINX HTTP and reverse proxy server...
Nov 03 09:32:32 ip-172-31-33-45 nginx[868]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Nov 03 09:32:32 ip-172-31-33-45 nginx[868]: nginx: configuration file /etc/nginx/nginx.conf test is successful
Nov 03 09:32:32 ip-172-31-33-45 systemd[1]: Started The NGINX HTTP and reverse proxy server.
```
工作正常，但是 curl 一下会得到 500。检查一下 log：
```text
admin@ip-172-31-33-45:/$ cat /var/log/nginx/error.log | tail -n 10
2022/09/11 16:39:11 [emerg] 5875#5875: unexpected ";" in /etc/nginx/sites-enabled/default:1
2022/09/11 16:54:26 [emerg] 5931#5931: unexpected ";" in /etc/nginx/sites-enabled/default:1
2022/09/11 16:55:00 [emerg] 5961#5961: unexpected ";" in /etc/nginx/sites-enabled/default:1
2022/09/11 17:02:07 [emerg] 6066#6066: unexpected ";" in /etc/nginx/sites-enabled/default:1
2022/09/11 17:07:03 [emerg] 6146#6146: unexpected ";" in /etc/nginx/sites-enabled/default:1
2022/11/03 09:30:47 [emerg] 584#584: unexpected ";" in /etc/nginx/sites-enabled/default:1
2022/11/03 09:32:32 [alert] 870#870: socketpair() failed while spawning "worker process" (24: Too many open files)
2022/11/03 09:32:32 [emerg] 871#871: eventfd() failed (24: Too many open files)
2022/11/03 09:32:32 [alert] 871#871: socketpair() failed (24: Too many open files)
2022/11/03 09:33:03 [crit] 871#871: *1 open() "/var/www/html/index.nginx-debian.html" failed (24: Too many open files), client: 127.0.0.1, server: _, request: "GET / HTTP/1.1", host: "127.0.0.1"
```
可以发现报错 Too many open files。搜了一下，网上提供的方法都试了一圈，问题不出在 nginx 的配置上。然后根据提示去看了 systemd 上 nginx 的配置：
```text
admin@ip-172-31-33-45:/$ cat /etc/systemd/system/nginx.service 
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true
LimitNOFILE=10

[Install]
WantedBy=multi-user.target
```
把 LimitNOFILE=10 改成 LimitNOFILE=1024，然后重启 nginx 即可正常得到响应：
```text
admin@ip-172-31-33-45:/$ sudo systemctl restart nginx
Warning: The unit file, source configuration file or drop-ins of nginx.service changed on disk. Run 'systemctl daemon-reload' to reload units.
admin@ip-172-31-33-45:/$ sudo systemctl daemon-reload
admin@ip-172-31-33-45:/$ sudo systemctl restart nginx
admin@ip-172-31-33-45:/$ curl -Is 127.0.0.1:80 | head -1
HTTP/1.1 200 OK
```

---

## "Salta"

> **Scenario:** "Salta": Docker container won't start.
> 
> **Level:** Medium
> 
> **Description:** There's a "dockerized" Node.js web application in the /home/admin/app directory. Create a Docker container so you get a web app on port :8888 and can curl to it. For the solution to be valid, there should be only one running Docker container.
> 
> **OS:** Debian 11

首先检查一下 docker 容器：
```text
admin@ip-172-31-38-21:/$ sudo docker ps -a
CONTAINER ID   IMAGE     COMMAND                  CREATED       STATUS                   PORTS     NAMES
124a4fb17a1c   app       "docker-entrypoint.s…"   6 weeks ago   Exited (1) 6 weeks ago             elated_taussig
admin@ip-172-31-38-21:~/app$ sudo docker logs 124
node:internal/modules/cjs/loader:928
  throw err;
  ^

Error: Cannot find module '/usr/src/app/serve.js'
    at Function.Module._resolveFilename (node:internal/modules/cjs/loader:925:15)
    at Function.Module._load (node:internal/modules/cjs/loader:769:27)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:76:12)
    at node:internal/main/run_main_module:17:47 {
  code: 'MODULE_NOT_FOUND',
  requireStack: []
}
```
发现报错了，Dockerfile 里出了一些问题，看一下：
```dockerfile
# documentation https://nodejs.org/en/docs/guides/nodejs-docker-webapp/

# most recent node (security patches) and alpine (minimal, adds to security, possible libc issues)
FROM node:15.7-alpine 

# Create app directory & copy app files
WORKDIR /usr/src/app

# we copy first package.json only, so we take advantage of cached Docker layers
COPY ./package*.json ./

# RUN npm ci --only=production
RUN npm install

# Copy app source
COPY ./* ./

# port used by this app
EXPOSE 8880

# command to run
CMD [ "node", "serve.js" ]
```
发现最后 CMD 里 server.js 打成了 serve.js，而且 EXPOSE 的端口也不对。两个问题修一下然后重新构建、运行：
```text
admin@ip-172-31-38-21:~/app$ sudo docker build -t app .
admin@ip-172-31-38-21:~/app$ sudo docker rm 124
admin@ip-172-31-38-21:~/app$ sudo docker run -d -p 8888:8888 app
e67b36ff14ff3676e419036180abf9231e97eacc5ec6fe9d76426e7003acfb8f
docker: Error response from daemon: driver failed programming external connectivity on endpoint nifty_bhaskara (ce8a09c7a42f730b89e0bd1bd3298de1598d79bf0d08d1532a7f38002cda84d4): Error starting userland proxy: listen tcp4 0.0.0.0:8888: bind: address already in use.
```
发现报错 8888 端口被占用了。没有 lsof，用 netstat 查一下端口：
```text
admin@ip-172-31-38-21:~/app$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      562/gotty           
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8888                 :::*                    LISTEN      -                   
tcp6       0      0 :::6767                 :::*                    LISTEN      563/sadagent        
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp6       0      0 fe80::8d3:45ff:fee9:546 :::*                                -                   
udp6       0      0 ::1:323                 :::*                                - 
```
发现 8888 端口在用，ps -aux 可以看到有一个 nginx 在运行，在 /etc/nginx/sites-enabled/default 里确实有使用 8888 端口。

所以先停掉 nginx，然后重新部署容器即可：
```text
admin@ip-172-31-38-21:~/app$ sudo systemctl stop nginx
admin@ip-172-31-38-21:~/app$ sudo docker stop e6
e6
admin@ip-172-31-38-21:~/app$ sudo docker rm e6
e6
admin@ip-172-31-38-21:~/app$ sudo docker run -d -p 8888:8888 app
...
admin@ip-172-31-38-21:~/app$ curl localhost:8888
Hello World!
```

---

## "Jakarta"

> **Scenario:** "Jakarta": it's always DNS.
> 
> **Level:** Hard
> 
> **Description:** Can't ping google.com. It returns ping: google.com: Name or service not known. Expected is being able to resolve the hostname. (Note: currently the VMs can't ping outside so there's no automated check for the solution).
> 
> **OS:** Ubuntu 22.04 LTS

根据题目知道是 dns 出了问题，/etc/resolv.conf 里的配置都没啥问题。而且整个 sadservers 是不能连接外网的，所以大概只能用本机的了。搜索了一下 dns 相关的配置文件，看了一圈发现 /etc/nsswitch.conf 里的 hosts 配置有问题：
```text
hosts:          files
```
而网上的例子里都有 dns，所以在 files 后面加一个 dns 就可以了：
```text
ubuntu@ip-172-31-42-233:/$ ping google.com
PING google.com (142.250.191.174) 56(84) bytes of data.
```

---

## "Bern"

> **Scenario:** "Bern": Docker web container can't connect to db container.
> 
> **Level:** Hard
> 
> **Description:** There are two Docker containers running, a web application (Wordpress or WP) and a database (MariaDB) as back-end, but if we look at the web page, we see that it cannot connect to the database. curl -s localhost:80 |tail -4 returns:
> 
> ```html
> <body id="error-page"> <div class="wp-die-message"><h1>Error establishing a database connection</h1></div></body> </html>
> ```
> 
> This is not a Wordpress code issue (the image is :latest with some network utilities added). What you need to know is that WP uses "WORDPRESS_DB_" environment variables to create the MySQL connection string. See the ./html/wp-config.php WP config file for example (from /home/admin).
> 
> **OS:** Debian 11

docker ps -a 可以看到有两个容器在运行。根据题目的 test 可以知道 mysql 的账号密码是 root:password。

WordPress 启动会从环境变量读取配置，所以在 wordpress 的容器中查一下 env：
```text
admin@ip-172-31-19-232:/$ sudo docker exec wordpress env |grep WORDPRESS_DB_
WORDPRESS_DB_PASSWORD=password
WORDPRESS_DB_USER=root
```
可以看出用户名和密码设置的是正确的。但是 NAME 和 HOST 使用的就是 wp-config.php 中默认的了，也就是 wordpress 和 mysql，NAME 的话在 mariadb 容器里可以看到确实是 wordpress，但 HOST 是 mysql，就连接不到了。

而题给的 test 一定要在 wordpress 容器里打开 mysqladmin，连接 host mysql。不知道怎么搞 qwq，hint 没再接着写了，八会 qwq。

---

## "Singara"

> **Scenario:** "Singara": Docker and Kubernetes web app not working.
> 
> **Level:** Hard
> 
> **Description:** There's a k3s Kubernetes install you can access with kubectl. The Kubernetes YAML manifests under /home/admin have been applied. The objective is to access from the host the "webapp" web server deployed and find what message it serves (it's a name of a town or city btw). In order to pass the check, the webapp Docker container should not be run separately outside Kubernetes as a shortcut.
> 
> **OS:** Debian 11

先看一下 k3s 的配置文件：

??? example "配置文件"
    ```yaml title="deployment.yml"
    apiVersion: apps/v1
    kind: Deployment
    metadata:
    name: webapp-deployment
    namespace: web
    spec:
    selector:
        matchLabels:
        app: webapp
    replicas: 1
    template:
        metadata:
        labels:
            app: webapp
        spec:
        containers:
        - name: webapp
            image: webapp
            imagePullPolicy: Always
            ports:
            - containerPort: 8880
    ```
    ```yaml title="namespace.yml"
    apiVersion: v1
    kind: Namespace
    metadata:
    name: web
    ```
    ```yaml title="nodeport.yml"
    apiVersion: v1
    kind: Service
    metadata:
    name: webapp-service
    namespace: web
    spec:
    type: NodePort
    selector:
        app.kubernetes.io/name: webapp
    ports:
        - port: 80
        targetPort: 8888
        nodePort: 30007
    ```

然后检查一下 k3s 各部分的状态：
```text
admin@ip-10-0-0-64:~$ kubectl get all -n web
NAME                                     READY   STATUS             RESTARTS   AGE
pod/webapp-deployment-666b67994b-5sffz   0/1     ImagePullBackOff   0          46d

NAME                     TYPE       CLUSTER-IP    EXTERNAL-IP   PORT(S)        AGE
service/webapp-service   NodePort   10.43.35.97   <none>        80:30007/TCP   46d

NAME                                READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/webapp-deployment   0/1     1            0           46d

NAME                                           DESIRED   CURRENT   READY   AGE
replicaset.apps/webapp-deployment-666b67994b   1         1         0       46d
```
可以发现 webapp-deployment 的镜像拉取失败了。因为它会从网络拉取 webapp 镜像而不是本地，而整个 sadservers 不能连接外部网络，所以自然会拉取失败。

这个状态和前一阵办 ZJUCTF 校赛很像，大概就是 k3s 拉取镜像的问题。当时是自建了一个 registry 来搞的。所以查一下本地的镜像：
```text
admin@ip-10-0-0-64:~$ sudo docker images
REPOSITORY   TAG        IMAGE ID       CREATED        SIZE
webapp       latest     9c082e2983bc   6 weeks ago    135MB
python       3.7-slim   c1d0bab51bbf   7 weeks ago    123MB
registry     2          3a0f7b0a13ef   2 months ago   24.1MB
```
发现正好有 registry 镜像。所以本地起一个 registry 然后将 webapp 上传：
```text
admin@ip-10-0-0-64:~$ sudo docker run -d -p 5000:5000 registry:2
...
admin@ip-10-0-0-64:~$ sudo docker tag webapp localhost:5000/webapp
admin@ip-10-0-0-64:~$ sudo docker push localhost:5000/webapp
Using default tag: latest
The push refers to repository [localhost:5000/webapp]
...
```
然后改一下 deployment.yml：
```yaml
...
template:
    metadata:
    labels:
        app: webapp
    spec:
    containers:
    - name: webapp
        image: localhost:5000/webapp # 这里
        imagePullPolicy: Always
        ports:
        - containerPort: 8888 # 和这里
```
然后应用：
```text
admin@ip-10-0-0-64:~$ kubectl apply -f deployment.yml 
deployment.apps/webapp-deployment configured
admin@ip-10-0-0-64:~$ kubectl get pods -n web
NAME                                 READY   STATUS        RESTARTS   AGE
webapp-deployment-666b67994b-5sffz   0/1     Terminating   0          46d
webapp-deployment-8f869f757-g2m7n    1/1     Running       0          12s
```
可以发现成功启动了，接下来的就是将其中的 8888 端口转发出来：
```text
admin@ip-10-0-0-64:~$ kubectl port-forward deployments/webapp-deployment 8888 -n web &
Forwarding from 127.0.0.1:8888 -> 8888
Forwarding from [::1]:8888 -> 8888
...
```
然后在另一个终端里 curl localhost:8888 就可以得到正常结果了。

---

## "Karakorum"

> **Scenario:** "Karakorum": WTFIT – What The Fun Is This?
> 
> **Level:** Hard
> 
> **Description:** There's a binary at /home/admin/wtfit that nobody knows how it works or what it does ("what the fun is this"). Someone remembers something about wtfit needing to communicate to a service in order to start. Run this wtfit program so it doesn't exit with an error, fixing or working around things that you need but are broken in this server. (Note that you can open more than one web "terminal").
> 
> **OS:** Debian 11

ls -l 可以看出来 wtfit 没有运行权限。所以先 chmod，但 chmod 会报错 bash: /usr/bin/chmod: Permission denied。经过检查可以发现是 /usr/bin/chmod 自身也没有运行权限：
```text
admin@ip-172-31-46-91:/$ ls -l /usr/bin/chmod
-rw-r--r-- 1 root root 64448 Sep 24  2020 /usr/bin/chmod
```
可以搜索到[一些解决办法](https://www.cnblogs.com/chuckzhang/p/9277268.html)：
```text
admin@ip-172-31-46-91:/$ sudo su
root@ip-172-31-46-91:/# /lib64/ld-linux-x86-64.so.2 /bin/chmod 755 /bin/chmod
root@ip-172-31-46-91:/# cd /home/admin/
root@ip-172-31-46-91:/home/admin# chmod +x wtfit
```
运行 wtfit 出错：ERROR: can't open config file。根据提示通过 strace 来跟踪得到错误的详细消息：
```text
admin@ip-172-31-46-91:~$ strace ./wtfit
...
openat(AT_FDCWD, "/home/admin/wtfitconfig.conf", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
...
```
在这个位置创建一个空的配置文件。然后再运行，还是出错：ERROR: can't connect to server。同样 strace 可以得到：
```text
admin@ip-172-31-46-91:~$ strace ./wtfit
...
connect(3, {sa_family=AF_INET, sin_port=htons(7777), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
...
```
所以可以看出它在试图连接 localhost:7777。开一个新的 terminal 然后监听一下 7777 端口，运行 wtfit：
```text
admin@ip-172-31-46-91:/$ nc -lvvp 7777
Listening on 0.0.0.0 7777
Connection received on localhost 54756
GET / HTTP/1.1
Host: localhost:7777
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip

```
可以发现就是简单的 GET，所以 python 起一个 http server，然后运行：
```text
admin@ip-172-31-46-91:/$ python3 -m http.server 7777
Serving HTTP on 0.0.0.0 port 7777 (http://0.0.0.0:7777/) ...
127.0.0.1 - - [03/Nov/2022 12:58:30] "GET / HTTP/1.1" 200 -
```
这时 wtfit 就可以正常运行结束了。

---

## "Hong-Kong"

> **Scenario:** "Hong-Kong": can't write data into database.
> 
> **Level:** Hard
> 
> **Description:** (Similar to "Manhattan" scenario but harder). Your objective is to be able to insert a row in an existing Postgres database. The issue is not specific to Postgres and you don't need to know details about it (although it may help).
> 
> Postgres information: it's a service that listens to a port (:5432) and writes to disk in a data directory, the location of which is defined in the data_directory parameter of the configuration file /etc/postgresql/14/main/postgresql.conf. In our case Postgres is managed by systemd as a unit with name postgresql.
> 
> **OS:** Debian 10

和前面的 "Manhattan" 类似。还是先检查状态没异常，重启没异常，查看 /var/log/syslog，发现：
```text
Nov  3 11:52:20 ip-172-31-25-11 systemd[1]: Starting PostgreSQL Cluster 14-main...
Nov  3 11:52:20 ip-172-31-25-11 postgresql@14-main[1318]: Error: /opt/pgdata/main is not accessible or does not exist
Nov  3 11:52:20 ip-172-31-25-11 systemd[1]: postgresql@14-main.service: Can't open PID file /run/postgresql/14-main.pid (yet?) after start: No such file or directory
Nov  3 11:52:20 ip-172-31-25-11 systemd[1]: postgresql@14-main.service: Failed with result 'protocol'.
Nov  3 11:52:20 ip-172-31-25-11 systemd[1]: Failed to start PostgreSQL Cluster 14-main.
```

找不到 /opt/pgdata/main，ls 一下 /opt/pgdata 也没有。再往前看 syslog 可以发现：
```text
Nov  3 11:47:54 ip-172-31-25-11 systemd[1]: dev-xvdb.device: Job dev-xvdb.device/start timed out.
Nov  3 11:47:54 ip-172-31-25-11 systemd[1]: Timed out waiting for device /dev/xvdb.
Nov  3 11:47:54 ip-172-31-25-11 systemd[1]: Dependency failed for /opt/pgdata.
Nov  3 11:47:54 ip-172-31-25-11 systemd[1]: opt-pgdata.mount: Job opt-pgdata.mount/start failed with result 'dependency'.
Nov  3 11:47:54 ip-172-31-25-11 systemd[1]: Startup finished in 2.669s (kernel) + 1min 31.106s (userspace) = 1min 33.776s.
Nov  3 11:47:54 ip-172-31-25-11 systemd[1]: dev-xvdb.device: Job dev-xvdb.device/start failed with result 'timeout'.
```
可以发现挂载设备超时了。

fdisk 看一下：
```text
root@ip-172-31-25-11:/# fdisk -l
Disk /dev/nvme0n1: 8 GiB, 8589934592 bytes, 16777216 sectors
Disk model: Amazon Elastic Block Store              
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/nvme1n1: 8 GiB, 8589934592 bytes, 16777216 sectors
Disk model: Amazon Elastic Block Store              
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 56507B41-5D22-1349-81AD-C628BA074922

Device           Start      End  Sectors  Size Type
/dev/nvme1n1p1  262144 16777182 16515039  7.9G Linux filesystem
/dev/nvme1n1p14   2048     8191     6144    3M BIOS boot
/dev/nvme1n1p15   8192   262143   253952  124M EFI System

Partition table entries are not in disk order.
root@ip-172-31-25-11:/# df
Filesystem      1K-blocks    Used Available Use% Mounted on
udev               228728       0    228728   0% /dev
tmpfs               47568    1524     46044   4% /run
/dev/nvme1n1p1    8026128 1230452   6366420  17% /
tmpfs              237828       0    237828   0% /dev/shm
tmpfs                5120       0      5120   0% /run/lock
tmpfs              237828       0    237828   0% /sys/fs/cgroup
/dev/nvme1n1p15    126710     278    126432   1% /boot/efi
```
可以发现 /dev/nvme0n1 没有挂载上，根据前面题目可以推测这个设备里面是 /opt/pgdata 的内容。

`mount /dev/nvme0n1 /opt/pgdata` 尝试挂载，没有报错，但仍旧没有东西。看一下 /var/log/syslog 发现：
```text
Nov  3 12:02:06 ip-172-31-25-11 kernel: [  945.914667] SGI XFS with ACLs, security attributes, realtime, no debug enabled
Nov  3 12:02:06 ip-172-31-25-11 kernel: [  945.925395] XFS (nvme0n1): Mounting V5 Filesystem
Nov  3 12:02:07 ip-172-31-25-11 kernel: [  946.092049] XFS (nvme0n1): Ending clean mount
Nov  3 12:02:07 ip-172-31-25-11 systemd[1]: opt-pgdata.mount: Unit is bound to inactive unit dev-xvdb.device. Stopping, too.
Nov  3 12:02:07 ip-172-31-25-11 systemd[1]: Unmounting /opt/pgdata...
Nov  3 12:02:07 ip-172-31-25-11 kernel: [  946.124665] XFS (nvme0n1): Unmounting Filesystem
Nov  3 12:02:07 ip-172-31-25-11 systemd[1]: opt-pgdata.mount: Succeeded.
Nov  3 12:02:07 ip-172-31-25-11 systemd[1]: Unmounted /opt/pgdata.
```

可以看出 systemd 不让我们挂载到 /opt/pgdata 上，因为它和 /dev/xvdb 设备关联了。这个关联是在 /etc/fstab 文件中的：
```text
# /etc/fstab: static file system information
UUID=5db68868-2d70-449f-8b1d-f3c769ec01c7 / ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1
UUID=72C9-F191 /boot/efi vfat defaults 0 0
/dev/xvdb /opt/pgdata xfs defaults,nofail 0 0
```
把里面的 /dev/xvdb 换成 /dev/nvme0n1，然后 systemctl daemon-reload 重新加载配置文件。之后就可以正常 mount 了：
```text
root@ip-172-31-25-11:/# systemctl daemon-reload
root@ip-172-31-25-11:/# ls /opt/pgdata
root@ip-172-31-25-11:/# mount /dev/nvme0n1 /opt/pgdata
root@ip-172-31-25-11:/# ls /opt/pgdata
deleteme  file1.bk  file2.bk  file3.bk  main
```
同样，这些 .bk 文件占满了空间，删掉然后重启 postgresql，就可以正常使用了：
```text
root@ip-172-31-25-11:/# ls -l /opt/pgdata
total 8285620
-rw-r--r--  1 root     root             69 May 21 22:20 deleteme
-rw-r--r--  1 root     root     7516192768 May 21 22:06 file1.bk
-rw-r--r--  1 root     root      967774208 May 21 22:17 file2.bk
-rw-r--r--  1 root     root         499712 May 21 22:23 file3.bk
drwx------ 19 postgres postgres       4096 May 21 22:24 main
root@ip-172-31-25-11:/# rm /opt/pgdata/file*.bk
root@ip-172-31-25-11:/# sudo systemctl start postgresql
root@ip-172-31-25-11:/# sudo -u postgres psql -c "insert into persons(name) values ('jane smith');" -d dt
INSERT 0 1
```

---

## "Venice"

> **Scenario:** "Venice": Am I in a container?
> 
> **Level:** Medium
> 
> **Description:** Try and figure out if you are inside a container (like a Docker one for example) or inside a Virtual Machine (like in the other scenarios).
> 
> **OS:** Debian 11

emmm，ps -aux 看到：
```text
root@ip-172-31-33-228:/# ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.4  2.0 100712  9600 ?        Ss   12:14   0:01 /sbin/init
root          22  0.0  1.4  26728  6912 ?        Ss   12:14   0:00 /lib/systemd/systemd-journald
message+      47  0.0  0.7   8268  3700 ?        Ss   12:14   0:00 /usr/bin/dbus-daemon --system --addres
root          49  0.0  1.1  13404  5532 ?        Ss   12:14   0:00 /lib/systemd/systemd-logind
root          71  0.0  2.4 1230092 11584 ?       S<sl 12:14   0:00 /usr/local/gotty --permit-write --reco
root          91  0.0  0.7   6056  3652 pts/0    S<s  12:18   0:00 bash
root          92  0.0  0.7   8840  3416 pts/0    R<+  12:18   0:00 ps -aux
```
和其它题目实例里面不一样，没有 kernel thread，所以是容器而不是虚拟机。（就这？

??? success "题给答案"
    > **Solution:** This is in fact a Podman container :-)  
    > You can get the image: docker.io/fduran/venice.
    > 
    > A way of checking is by looking at the environment of the PID=1 process and see if there's a container variable, for ex: cat /proc/1/environ|tr "\0" "\n"|grep container , in our case would be container=podman but I changed its value.
    > 
    > An indicator is to look at the running processes and see that there are no kernel threads like [kthreadd].

## "Oaxaca"

> **Scenario:** "Oaxaca": Close an Open File
> 
> **Level:** Medium
> 
> **Description:** The file /home/admin/somefile is open for writing by some process. Close this file without killing the process.
> 
> **OS:** Debian 11

lsof /home/admin/somefile 可以看到有进程打开了这个文件：
```text
COMMAND PID  USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME
bash    798 admin   77w   REG  259,1        0 272875 /home/admin/somefile
```
ps -aux 找一通发现这个 PID 就是当前的 shell。

somefile 旁边还有一个 openfile.sh，内容为：
```shell
#!/bin/bash
exec 66> /home/admin/somefile
```
可以推测是以这种方式打开的文件。通过前面 lsof 的结果知道这个文件的 fd 为 77，或者可以通过 proc 来验证一下：
```text
$ ls -l /proc/self/fd
total 0
lrwx------ 1 admin admin 64 Dec 24 04:47 0 -> /dev/pts/0
lrwx------ 1 admin admin 64 Dec 24 04:47 1 -> /dev/pts/0
lrwx------ 1 admin admin 64 Dec 24 04:47 2 -> /dev/pts/0
lr-x------ 1 admin admin 64 Dec 24 04:47 3 -> /proc/819/fd
l-wx------ 1 admin admin 64 Dec 24 04:47 77 -> /home/admin/somefile
```
然后同样使用 exec 关掉 77 fd 就好了：
```shell
$ exec 77>&-
```

## "Melbourne"

> **Scenario:** "Melbourne": WSGI with Gunicorn
> 
> **Level:** Medium
> 
> **Description:** There is a Python WSGI web application file at /home/admin/wsgi.py , the purpose of which is to serve the string "Hello, world!". This file is served by a Gunicorn server which is fronted by an nginx server (both servers managed by systemd). So the flow of an HTTP request is: Web Client (curl) -> Nginx -> Gunicorn -> wsgi.py . The objective is to be able to curl the localhost (on default port :80) and get back "Hello, world!", using the current setup.
> 
> **OS:** Debian 11

首先 curl -v http://localhost 看一下，发现 Connection refused：
```text
admin@ip-172-31-32-71:~$ curl -v http://localhost
*   Trying 127.0.0.1:80...
* connect to 127.0.0.1 port 80 failed: Connection refused
* Failed to connect to localhost port 80: Connection refused
* Closing connection 0
curl: (7) Failed to connect to localhost port 80: Connection refused
```
查询一下 nginx 状态，发现是没有开启，所以 sudo 重启：
```text
admin@ip-172-31-32-71:~$ systemctl status nginx
● nginx.service - A high performance web server and a reverse proxy server
     Loaded: loaded (/lib/systemd/system/nginx.service; disabled; vendor preset:>
     Active: inactive (dead)
       Docs: man:nginx(8)
admin@ip-172-31-32-71:~$ sudo systemctl start nginx
admin@ip-172-31-32-71:~$ systemctl status nginx.service
● nginx.service - A high performance web server and a reverse proxy server
     Loaded: loaded (/lib/systemd/system/nginx.service; disabled; vendor preset: enabled)
     Active: active (running) since Sat 2022-12-24 05:09:46 UTC; 3s ago
       Docs: man:nginx(8)
    Process: 850 ExecStartPre=/usr/sbin/nginx -t -q -g daemon on; master_process on; (code=exited, status=0/SUCCESS)
    Process: 851 ExecStart=/usr/sbin/nginx -g daemon on; master_process on; (code=exited, status=0/SUCCESS)
   Main PID: 852 (nginx)
      Tasks: 3 (limit: 524)
     Memory: 3.1M
        CPU: 36ms
     CGroup: /system.slice/nginx.service
             ├─852 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
             ├─853 nginx: worker process
             └─854 nginx: worker process
```
可以正常重启，但这时 curl 会出现 502。看一下 /etc/nginx/sites-enabled/default 里的配置：
```nginx
server {
    listen 80;

    location / {
        include proxy_params;
        proxy_pass http://unix:/run/gunicorn.socket;
    }
}
```
发现只有 proxy_pass 那句可能出问题。systemctl 查询一下 gunicorn 状态：
```text
admin@ip-172-31-32-71:~$ systemctl status gunicorn
● gunicorn.service - gunicorn daemon
     Loaded: loaded (/etc/systemd/system/gunicorn.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2022-12-24 05:01:16 UTC; 10min ago
TriggeredBy: ● gunicorn.socket
   Main PID: 550 (gunicorn)
      Tasks: 2 (limit: 524)
     Memory: 17.1M
        CPU: 348ms
     CGroup: /system.slice/gunicorn.service
             ├─550 /usr/bin/python3 /usr/local/bin/gunicorn --bind unix:/run/gunicorn.sock wsgi
             └─612 /usr/bin/python3 /usr/local/bin/gunicorn --bind unix:/run/gunicorn.sock wsgi

Dec 24 05:01:16 ip-172-31-32-71 systemd[1]: Started gunicorn daemon.
Dec 24 05:01:17 ip-172-31-32-71 gunicorn[550]: [2022-12-24 05:01:17 +0000] [550] [INFO] Starting gunicorn 20.1.0
Dec 24 05:01:17 ip-172-31-32-71 gunicorn[550]: [2022-12-24 05:01:17 +0000] [550] [INFO] Listening at: unix:/run/gunicorn.sock (550)
Dec 24 05:01:17 ip-172-31-32-71 gunicorn[550]: [2022-12-24 05:01:17 +0000] [550] [INFO] Using worker: sync
Dec 24 05:01:17 ip-172-31-32-71 gunicorn[612]: [2022-12-24 05:01:17 +0000] [612] [INFO] Booting worker with pid: 612
```
可以看出实际上是绑定在 /run/gunicorn.sock 上了，/run/gunicorn.socket 并不存在。所以修改 nginx 的配置然后 restart。这时 curl 不会报错，但没有内容，-v 输出：
```text
admin@ip-172-31-32-71:~$ curl -v http://localhost
*   Trying 127.0.0.1:80...
* Connected to localhost (127.0.0.1) port 80 (#0)
> GET / HTTP/1.1
> Host: localhost
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0
< Date: Sat, 24 Dec 2022 05:13:05 GMT
< Content-Type: text/html
< Content-Length: 0
< Connection: keep-alive
< 
* Connection #0 to host localhost left intact
```
可以看到是 200，但这里 Response 里有 Content-Length: 0，所以什么都没得到。发现这个是写在 wsgi.py 里的：
```text
admin@ip-172-31-32-71:~$ cat wsgi.py 
def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html'), ('Content-Length', '0'), ])
    return [b'Hello, world!']
```
所以把 ('Content-Length', '0') 去掉，然后 sudo systemctl restart gunicorn 重启，这次再 curl 就正常了：
```text
admin@ip-172-31-32-71:~$ curl -s http://localhost
Hello, world!
```

## "Lisbon"

> **Scenario:** "Lisbon": etcd SSL cert troubles
> 
> **Level:** Medium
> 
> **Description:** There's an etcd server running on https://localhost:2379 , get the value for the key "foo", ie `etcdctl get foo` or `curl https://localhost:2379/v2/keys/foo`
> 
> **OS:** Debian 11

首先跑一下 `etcdctl get goo` 试试看，得到报错：
```text
admin@ip-10-0-0-138:/$ etcdctl get foo
Error:  client: etcd cluster is unavailable or misconfigured; error #0: x509: certificate has expired or is not yet valid: current time 2024-02-20T02:49:48Z is after 2023-01-30T00:02:48Z

error #0: x509: certificate has expired or is not yet valid: current time 2024-02-20T02:49:48Z is after 2023-01-30T00:02:48Z
```

可见是证书过期了，而且当前时间是在 24 年，直接 `sudo date -s 20230101` 修改日期到证书过期前就可以。

接着再运行可以得到：
```text
admin@ip-10-0-0-138:/$ etcdctl get foo
Error:  client: response is invalid json. The endpoint is probably not valid etcd cluster endpoint.
admin@ip-10-0-0-138:/$ curl https://localhost:2379/v2/keys/foo
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
```

这个 curl 的 404 结果是 nginx 的就比较怪，所以 curl 了一下根页面：
```
admin@ip-10-0-0-138:/$ curl https://localhost:2379/
Testing SSL
admin@ip-10-0-0-138:/$ curl https://localhost:443/
Testing SSL
admin@ip-10-0-0-138:/$ cat /var/www/html/index.html 
Testing SSL
```

可以猜测 2379 端口被重定向到 nginx 的 443 端口上了，看了下 `/etc/nginx/sites-enabled/default` 并没有 2379 端口相关设置，netstat 也只可以看到占用情况，2379 确实在用。接下来看看 iptables：
```text
admin@ip-10-0-0-138:/$ sudo iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         
DOCKER     all  --  anywhere             anywhere             ADDRTYPE match dst-type LOCAL

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
REDIRECT   tcp  --  anywhere             anywhere             tcp dpt:2379 redir ports 443
DOCKER     all  --  anywhere            !ip-127-0-0-0.us-east-2.compute.internal/8  ADDRTYPE match dst-type LOCAL

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination         
MASQUERADE  all  --  ip-172-17-0-0.us-east-2.compute.internal/16  anywhere            

Chain DOCKER (2 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere
```
可以发现 `tcp dpt:2379 redir ports 443`，所以最简单的方法直接 -F flush 掉这些 rules 就好：
```text
admin@ip-10-0-0-138:/$ sudo iptables -t nat -F       
admin@ip-10-0-0-138:/$ etcdctl get foo
bar
admin@ip-10-0-0-138:/$ curl https://localhost:2379/v2/keys/foo
{"action":"get","node":{"key":"/foo","value":"bar","modifiedIndex":4,"createdIndex":4}}
```

## "Pokhara"

> **Scenario:** "Pokhara": SSH and other sshenanigans
> 
> **Level:** Hard
> 
> **Description:** A user `client` was added to the server, as well as their SSH public key. The objective is to be able to SSH locally (there's only one server) as this user client using their ssh keys. This is, if as root you change to this user `sudo su; su client`, you should be able to login with ssh: `ssh localhost`.
> 
> **OS:** Debian 11

首先测试一下，发现连切换到 client 用户都不可以：
```text
admin@ip-172-31-33-16:/$ sudo su
root@ip-172-31-33-16:/# su client
Your account has expired; please contact your system administrator.
```

用户过期了，那就延一下：
```text
admin@ip-172-31-33-16:/$ sudo chage -l client
Last password change                                    : Feb 05, 2023
Password expires                                        : never
Password inactive                                       : never
Account expires                                         : Jan 01, 1970
Minimum number of days between password change          : 0
Maximum number of days between password change          : 99999
Number of days of warning before password expires       : 7
admin@ip-172-31-33-16:/$ sudo usermod -e 2024-01-01 client
admin@ip-172-31-33-16:/$ sudo chage -l client
Last password change                                    : Feb 05, 2023
Password expires                                        : never
Password inactive                                       : never
Account expires                                         : Jan 01, 2024
Minimum number of days between password change          : 0
Maximum number of days between password change          : 99999
Number of days of warning before password expires       : 7
```

再次登陆，出现报错：
```text
root@ip-172-31-33-16:/# su client
su: failed to execute /usr/sbin/nologin: Resource temporarily unavailable
```
它试图执行 `/usr/sbin/nologin`，但是正常来讲应该是一个 shell，所以改一下先，但仍然会出现报错：
```text
root@ip-172-31-33-16:/# lslogins client
...                 
Shell:                              /usr/sbin/nologin                   
...
root@ip-172-31-33-16:/# usermod --shell /bin/bash client
root@ip-172-31-33-16:/# lslogins client
...
Shell:                              /bin/bash                           
...
root@ip-172-31-33-16:/# su client
su: failed to execute /bin/bash: Resource temporarily unavailable
```

搜索了解到可能是登陆数量被限制了，在 `/etc/security/limits.conf` 中发现：
```text
client          hard    nproc           0
```
注释掉这一行，可以登陆 client 用户了，但是 ssh 还有问题：
```text
root@ip-172-31-33-16:/# su client
client@ip-172-31-33-16:/$ ssh localhost
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ECDSA key sent by the remote host is
SHA256:nfWAp8P5xQ+rJbfolHi8/jTpKNa+DlN1MXv1Wwus+4M.
Please contact your system administrator.
Add correct host key in /home/client/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /home/client/.ssh/known_hosts:1
  remove with:
  ssh-keygen -f "/home/client/.ssh/known_hosts" -R "localhost"
ECDSA host key for localhost has changed and you have requested strict checking.
Host key verification failed.
```
根据指导，在 client 用户下执行 ssh-keygen：
```text
client@ip-172-31-33-16:/$ ssh-keygen -f "/home/client/.ssh/known_hosts" -R "localhost"
# Host localhost found: line 1
/home/client/.ssh/known_hosts updated.
Original contents retained as /home/client/.ssh/known_hosts.old
client@ip-172-31-33-16:/$ ssh localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:nfWAp8P5xQ+rJbfolHi8/jTpKNa+DlN1MXv1Wwus+4M.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
client@localhost: Permission denied (publickey).
```

又 Permission denied，所以去查一下 ssh 的配置文件：
```text
root@ip-172-31-33-16:/# cat /etc/ssh/sshd_config.d/sad.conf
DenyUsers client
```
删掉这一行，`systemctl restart ssh` 重启服务，再次尝试，得到：
```text
client@ip-172-31-33-16:/$ ssh localhost
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '/home/client/.ssh/id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "/home/client/.ssh/id_rsa": bad permissions
client@localhost: Permission denied (publickey).
client@ip-172-31-33-16:/$ ls -l /home/client/.ssh/id_rsa
-rw-r--r-- 1 client client 2610 Feb  5 22:33 /home/client/.ssh/id_rsa
```
它告诉我们 id_rsa 的权限太大了，因此给 group 和 others 的 r 权限都去掉：
```text
client@ip-172-31-33-16:/$ chmod g-r /home/client/.ssh/id_rsa
client@ip-172-31-33-16:/$ chmod o-r /home/client/.ssh/id_rsa
```
即可正常 ssh 登陆：
```text
client@ip-172-31-33-16:/$ ssh localhost
Linux ip-172-31-33-16 5.10.0-14-cloud-amd64 #1 SMP Debian 5.10.113-1 (2022-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Feb  5 23:00:41 2023 from 127.0.0.1
```

## "Roseau"

> **Scenario:** "Roseau": Hack a Web Server
> 
> **Level:** Hard
> 
> **Description:** There is a secret stored in a file that the local Apache web server can provide. Find this secret and have it as a /home/admin/secret.txt file.
> 
> Note that in this server the admin user is not a sudoer.
> 
> Also note that the password crackers Hashcat and Hydra are installed from packages and John the Ripper binaries have been built from source in /home/admin/john/run.
> 
> **OS:** Debian 11

Sadservers 上第一道 Hack 类题目的题，不过看起来目的也很明确，区别基本就是没有 root 权限，需要绕过、破解等。

既然有一个 Apache 服务，那就先 curl 一下 localhost：
```text
admin@ip-172-31-34-168:~$ curl localhost
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at localhost Port 80</address>
</body></html>
```
需要认证，而 Apache 的配置文件是可以直接看到的：
```text
admin@ip-172-31-34-168:/$ cat /etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined


        <Directory "/var/www/html">
                AuthType Basic
                AuthName "Protected Content"
                AuthUserFile /etc/apache2/.htpasswd
                Require valid-user
        </Directory>
</VirtualHost>
```
所以整个目录都被保护了，使用 `/etc/apache2/.htpasswd` 中的账号密码才能访问。而这个文件我们也是可以直接访问的：
```text
admin@ip-172-31-34-168:/$ cat /etc/apache2/.htpasswd
carlos:$apr1$b1kyfnHB$yRHwzbuKSMyW62QTnGYCb0
```
题目里说了提供了 John the Ripper，搜一下可以知道这是个破解密码的工具，直接把 .htpasswd 文件丢进去：
```text
admin@ip-172-31-34-168:/$ cd ~/john/run/
admin@ip-172-31-34-168:~/john/run$ ./john /etc/apache2/.htpasswd
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Warning: Only 34 candidates buffered for the current salt, minimum 48 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
0g 0:00:00:00 DONE 1/3 (2023-02-20 03:59) 0g/s 9527p/s 9527c/s 9527C/s Carlos1921..Carlos1900
Proceeding with wordlist:./password.lst
Enabling duplicate candidate password suppressor
chalet           (carlos)     
1g 0:00:00:01 DONE 2/3 (2023-02-20 03:59) 0.6097g/s 40560p/s 40560c/s 40560C/s 050381..song
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
得到用户 carlos 的密码 chalet，然后通过 -u 选项来 curl：
```text
admin@ip-172-31-34-168:~/john/run$ curl -u carlos:chalet localhost
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /</title>
 </head>
 <body>
<h1>Index of /</h1>
 ...
</body></html>
```
可以成功认证，然后列一下 `/var/www/html` 的内容，发现有一个 webfile，curl 下来：
```text
admin@ip-172-31-34-168:~/john/run$ ls /var/www/html/
webfile
admin@ip-172-31-34-168:~/john/run$ curl -u carlos:chalet localhost/webfile
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.
admin@ip-172-31-34-168:~/john/run$ curl -u carlos:chalet localhost/webfile --output ~/secret
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   215  100   215    0     0   104k      0 --:--:-- --:--:-- --:--:--  104k
```
file 一下发现 secret 是个 zip，但 unzip 需要密码：
```text
admin@ip-172-31-34-168:~$ file secret
secret: Zip archive data, at least v1.0 to extract
admin@ip-172-31-34-168:~$ unzip secret
Archive:  secret
[secret] secret.txt password:
```
同样可以使用 John the Ripper 来破解：
```text
admin@ip-172-31-34-168:~$ john/run/zip2john secret > secret.passwd
ver 1.0 efh 5455 efh 7875 secret/secret.txt PKZIP Encr: 2b chk, TS_chk, cmplen=29, decmplen=17, crc=AAC6E9AF ts=14E0 cs=14e0 type=0
admin@ip-172-31-34-168:~$ john/run/john secret.passwd 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
0g 0:00:00:00 DONE 1/3 (2023-02-20 04:03) 0g/s 470700p/s 470700c/s 470700C/s Txtsecret/secret.txt1900..Tsecret1900
Proceeding with wordlist:john/run/password.lst
Enabling duplicate candidate password suppressor
andes            (secret/secret.txt)     
1g 0:00:00:00 DONE 2/3 (2023-02-20 04:03) 2.777g/s 1529Kp/s 1529Kc/s 1529KC/s poussinet..nisa1234
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
admin@ip-172-31-34-168:~$ unzip secret
Archive:  secret
[secret] secret.txt password: andes
 extracting: secret.txt              
admin@ip-172-31-34-168:~$ ls
agent  john  secret  secret.passwd  secret.txt
admin@ip-172-31-34-168:~$ cat secret.txt
Roseau, Dominica
admin@ip-172-31-34-168:~$ sha1sum /home/admin/secret.txt |awk '{print $1}'
cc2c322fbcac56923048d083b465901aac0fe8f8
```