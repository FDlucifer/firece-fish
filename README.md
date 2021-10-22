# fierce-fish  [![Python 3.9](https://img.shields.io/badge/python-3.9-yellow.svg)](https://www.python.org/)

fierce-fish是由TCC(斗象能力中心)出品并维护的开源漏洞检测框架osprey的改写，去掉臃肿功能的精简版本poc框架

 - PS：真的用不惯其它臃肿的功能，不过作为一个收集漏洞poc && exp的框架还是非常不错的！！！

 - [osprey](https://github.com/TophantTechnology/osprey)

### 简介

fierce-fish ------ 凶鱼，一种比鱼鹰还要凶猛的鱼，由于是osprey的改写版所以取此命名漏洞盒子PoC框架，寓意快，精，准，凶。

fierce-fish 是一个可无限扩展自定义poc的开源漏洞检测与利用框架(Python3开发)，是osprey的修改版。 fierce-fish框架可供使用者在渗透测试、漏洞检测、漏洞扫描等场景中应用。框架提供了命令行接口，可供灵活调用，也可用于构建自己的扫描器, 构建自己的通用型漏洞库。

***持续添加POC && EXP***

### 安装

从Git上获取最新版本的osprey代码

``` bash
$ git clone https://github.com/FDlucifer/firece-fish.git
$ cd firece-fish
$ pip3 install -r requirements.txt
```

 - 若执行脚本还是报错，可以根据报错信息提示缺失的模块，手动执行命令(pip3 install ‘缺失模块名')，进行安装...

### 使用

- 获取帮助列表：

``` bash
$ python osprey.py --help
```

- 最简单的用法，针对一个目标URL，发起一个PoC做检测：

``` bash
$ python osprey.py -t URL -v POC_ID
```

### 目前已收录漏洞POC及EXP



### 特点

 1. 体积小
 - ![](pics/1.png)
 2. 检测效果精准，可自己持续按照框架模版添加poc, 方便高效
 - ![](pics/2.png)

### poc编写说明相关文档

基于[Osprey](https://github.com/TophantTechnology/osprey/)编写PoC，请参考 [osprey编写规范和要求说明](doc/PoC_specification.md)

### 后续会在本仓库长期更新最新的POC & EXP。:)