![image-20240201140450649](https://github.com/qingsmoke/NAE/blob/main/image-20240201140450649.png)

## 📖简介

**NAE** （网络资产提取小工具   Network Asset Extraction）

Python编写的网络资产提取小工具，适用于安全测试人员前期对表格中的资产进行提取，基于正则表达式识别，提取出URL、域名、IP，去重后分别保存至txt文件中

| 可识别的资产格式有以下范围：                     |
| :----------------------------------------------- |
| 1.test.com                                       |
| 2.test.com                                       |
| http://2.test.com                                |
| https://2.test.com/test/test                     |
| 1.1.1.1/6,1.1.1.1/24，1.1.1.0/24                 |
| 1.1.1.1-2，1.1.1.1-3，1.1.1.1--4                 |
| 1.1.1.1:80\|443,1.1.1.2:80\|443，1.1.1.3:80\|443 |

## 🚍使用

> 说明

目前输出文件默认保存在当前目录下，现只支持输出txt文件

> 安装依赖

```
pip3 install -r requirements.txt
```

> 命令行

```
usage: python3 NAE.py -f [文本名称] （默认自动提取URL、域名、IP）
 （注:  使用时必须带有 -f [文本名称]，暂只支持xlsx、xls、csv表格文件）

others:
  -h, --help            显示帮助

target:
  -u, --url             仅提取表格中的URL
  -d, --domain          仅提取表格中的域名
  -i, --ip              仅提取表格中的IP
  -f, --filename        打开xlsx、xls、csv文件

example:
  -u , --url            python3 NAE.py -u -f test.xlsx    仅提取表格中的URL
  -u , --url            python3 NAE.py --url --filename=test.xlsx    仅提取表格中的URL
  -f , --filename       python3 NAE.py -f test.xlsx    提取表格中的URL、域名、IP
  -f , --filename       python3 NAE.py --filename=test.xlsx  提取表格中的URL、域名、IP
```

## ⏰个人想说的话

这是我个人的练手项目，想到什么就写什么了，感觉帅就完了！！！

项目先保证能跑，以后再慢慢优化吧，哈哈，见谅见谅，有什么需求和建议可以在`Issues`中提的哦！如果有更好的方式筛选资产，也会重构的喔！

写这个来联手项目的目的呢。也是因为有时候我拿到的测试资产，格式不是我想要的，一旦量大，要再手工导出资产，费时费力，影响效率...目前将遇到的场景写出来，就能够很好的匹配出资产，导出txt文件后，马上拿去扫描

未来如果遇到别的场景，会加进去，写成大工具！！个人能想到的拓展功能有：

​	1、接收各类文件（TXT、JSON、XML ...）

​	2、输出各类型文件（CSV、XLSX、JSON、XML ...）

​	3、继续优化匹配功能，在更为复杂的资产格式中提取出域名、URL、IP

​	4、增加多线程处理

​	5、整理旧表格，输出新表格

​	6、仅去重功能

​	7、仅提取主域名功能

​	8、与其他工具进行联动功能

​	.....
