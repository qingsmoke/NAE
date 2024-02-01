#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import ipaddress
import argparse
import pandas as pd
from colorama import Fore


VERSION = '1.0'

R = '\033[31m'  # red 红色
G = '\033[32m'  # green 绿色
C = '\033[36m'  # cyan 青色
W = '\033[0m'  # white 白色
Y = '\033[33m'  # yellow 黄色


banner = r'''
 ███▄    █   ▄▄▄     ▓████████▓
 ██ ▀█   █  ▒████▄     ▓█    ▀ 
▓██  ▀█ ██ ▒▒██  ▀█▄   ▒████   
▓██▒  ▐▌██ ▒░██▄▄▄▄██  ▒█▓   ▄ 
▒██░   ▓██ ░ ▓█   ▓██ ▒░███████
░ ▒░   ▒ ▒   ▒▒   ▓▒█ ░░░ ▒░ ░
░ ░░   ░ ▒ ░  ▒   ▒▒  ░ ░ ░  ░
   ░   ░ ░    ░   ▒       ░   
         ░        ░   ░   ░  ░
     （网络资产提取小工具）
  （Network Asset Extraction）
'''


def print_banners():
    """ 打印 banners """
    print(f'{R}{banner}{W}')
    print(f'{Y}[*] Version : {W}{VERSION}\n')


def process_excel_datas(file_path):
    """ 读取表格文件中的数据 """
    # 初始化一个空字符串用于存储所有数据
    all_data = []

    try:
        # 根据文件扩展名判断文件类型
        file_extension = file_path.split('.')[-1]
        if file_extension == 'csv':
            # 读取CSV文件
            df = pd.read_csv(file_path, encoding='GBK')  # 如果文本字体不对，请修改encoding

        else:
            # 读取Excel文件中的sheet1表（支持XLSX和XLS）
            df = pd.read_excel(file_path, sheet_name=0, engine="openpyxl")

        for column in df.columns:
            # 直接遍历列名
            # 获取列数据并删除NaN值
            data = df[column].dropna()
            # 将Series转换为字符串列表
            strings = data.astype(str).tolist()

            # 遍历字符串列表，处理可能存在的逗号或空格分隔的数据
            for s in strings:
                # 先将空格替换为逗号，然后分割，同时去除空行
                split_strings = [part.strip() for part in s.replace(" ", ",").split(",") if part.strip()]
                # 将分割后的每个部分作为独立的行添加到all_rows中
                all_data.extend(split_strings)

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')

    return all_data  # 返回一个大的字符串


def domain_matches(text_list):
    """ 域名匹配 """
    pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'   # 域名正则表达式
    all_domain = []
    # print(text_list)

    try:
        for text in text_list:
            # print(text)
            extract = re.findall(pattern, text)
            # 过滤空格
            filtered = [e for e in extract if e]
            all_domain.extend(filtered)

        # 去重再输出保存
        result = deduplication(all_domain)
        # print(result)
        out_filename = 'domains.txt'
        texts = output_file(result, out_filename)
        print(texts)

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')
    # print(all_extract)
    # return all_domain


def url_matches(text_list):
    """ URL匹配 """
    pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'      # URL正则表达式
    all_url = []
    # print(text_list)

    try:
        for text in text_list:
            # print(text)
            extract = re.findall(pattern, text)
            # 过滤空格
            filtered = [e for e in extract if e]
            all_url.extend(filtered)

        # 去重再输出保存
        result = deduplication(all_url)
        # print(result)
        out_filename = 'urls.txt'
        texts = output_file(result, out_filename)
        print(texts)

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')
    # print(all_extract)
    return all_url


def ip_matches(text_list):
    """ IP匹配 """
    pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}.*$\b'   # IP正则表达式
    all_ip = []

    try:
        for text in text_list:
            extract = re.findall(pattern, text)
            # 过滤空格
            filtered = [e for e in extract if e]
            all_ip.extend(filtered)

        # 去重再输出保存
        external_ips = expand_ip_ranges(all_ip)
        result = deduplication(external_ips)
        out_filename = 'ips.txt'
        texts = output_file(result, out_filename)
        print(texts)

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')


def expand_ip_ranges(ip_ranges):
    """整理带有特殊字符的IP地址，并且自动填充IP区间"""
    expanded_ips = []
    valid_external_ips = []  # 用于存储有效的外网IP地址

    try:
        for ip_range in ip_ranges:
            # print(ip_range)
            if '.1/' in ip_range or '.0/' in ip_range or re.search(r'.1/24', ip_range)\
                    or re.search(r'.0/24', ip_range):   # 筛选带有.1/、.0/、.1/24、.0/24的IP，自动补齐IP区
                network = ipaddress.IPv4Network(ip_range.replace('.1/', '.0/'), strict=False)
                expanded_ips.extend(str(ip) for ip in network.hosts())

            # 筛选带有/ - —的IP，自动补齐IP区间
            elif '/' in ip_range or re.search(r'.*-', ip_range) or re.search(r'.*—', ip_range):
                if '/' in ip_range:
                    ip_range = re.sub(r'/+', '/', ip_range)
                    base_ip, last_octet = ip_range.split('/')  # 分割
                    parts = base_ip.split('.')
                    base_int = int(parts[-1])
                    last_int = int(last_octet)
                    if base_int > last_int or last_int - base_int > 255:
                        raise ValueError(f"无效范围: {ip_range}")
                    for i in range(base_int, min(last_int + 1, 255)):
                        parts[-1] = str(i)
                        expanded_ip = '.'.join(parts)
                        expanded_ips.append(expanded_ip)

                elif '-' in ip_range:
                    ip_range = re.sub(r'-+', '-', ip_range)  # 去除多余的连字符
                    base_ip, last_octet = ip_range.split('-')
                    parts = base_ip.split('.')
                    base_int = int(parts[-1])
                    last_int = int(last_octet)
                    if base_int > last_int or last_int - base_int > 255:
                        raise ValueError(f"无效范围: {ip_range}")
                    for i in range(base_int, min(last_int + 1, 255)):
                        parts[-1] = str(i)
                        expanded_ip = '.'.join(parts)
                        expanded_ips.append(expanded_ip)

                elif '—' in ip_range:
                    ip_range = re.sub(r'—+', '—', ip_range)  # 去除多余的连字符
                    base_ip, last_octet = ip_range.split('—')
                    # print(ip_range)
                    parts = base_ip.split('.')
                    base_int = int(parts[-1])
                    last_int = int(last_octet)

                    if base_int > last_int or last_int - base_int > 255:
                        raise ValueError(f"无效范围: {ip_range}")
                    for i in range(base_int, min(last_int + 1, 255)):
                        parts[-1] = str(i)
                        expanded_ip = '.'.join(parts)
                        # print(expanded_ip)
                        expanded_ips.append(expanded_ip)

            else:
                if ":" in ip_range or "：" in ip_range:
                    ip_range = re.sub(r"[：:](\d+.*?)?$", "", ip_range)  # 去除多余的连字符
                    # print(ip_range)
                expanded_ips.append(ip_range)   # 如果资产IP格式，可以在这里添加处理逻辑

        """ 从IP地址列表中去除重复IP和内网IP，返回有效的外网IP列表 """
        for ip in expanded_ips:
            if not is_private_ip(ip):  # 如果不是内网IP，则添加到valid_external_ips集合中
                valid_external_ips.append(ip)

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')

    return valid_external_ips


def is_private_ip(ip):
    """ 判断IP地址是否是内网地址 """
    private_ips = [
        # 范围：10.x.x.x
        re.compile(r'^10\.(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d{2}'
                   r'|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$'),
        # 范围：172.(16-31).x.x
        re.compile(r'^172\.(1[6-9]|2\d|3[01])\.(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$'),
        # 范围：192.168.x.x
        re.compile(r'^192\.168\.\d{1,3}.*$')
    ]

    try:
        for regex in private_ips:
            if regex.match(ip):
                return True

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')

    return False


def deduplication(text_list):
    """ 去重 """
    # 用于快速检查是否已经看到过这行
    seen_lines = set()
    # 存储唯一行的列表，保持它们的原始顺序
    unique_lines = []

    try:
        for line in text_list:
            # 如果这行之前没有出现过，则将其添加到结果列表和已见过的集合中
            if line not in seen_lines:
                seen_lines.add(line)
                unique_lines.append(line)

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')

    return unique_lines


def output_file(result_list, filename):
    """ 保存为txt文件 """
    # 将匹配项列表写入到文本文件中
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            for r in result_list:
                print(f'{G} [+] 正在保存：{W}{r}')
                file.write(r + '\n')

    except IndexError as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')

    return f"\n{Fore.GREEN}[+] {G}恭喜您提取成功!文本保存为{filename}，接下来就可以愉快的渗透了！{Fore.RESET}"


def arguments():
    """ 命令行 """
    parser = argparse.ArgumentParser(usage="python3 NAE.py -f [文本名称] （默认自动提取URL、域名、IP）\n"
                                           " （注: 使用时必须带有 -f [文本名称]，暂只支持xlsx、xls、csv表格文件）", add_help=False)

    others = parser.add_argument_group("others")
    others.add_argument('-h', '--help', action="help", help="显示帮助")

    target = parser.add_argument_group("target")
    target.add_argument('-u', '--url', action='store_true', help="仅提取表格中的URL")
    target.add_argument('-d', '--domain', action='store_true', help="仅提取表格中的域名")
    target.add_argument('-i', '--ip', action='store_true', help="仅提取表格中的IP")
    target.add_argument('-f', '--filename', action='store', metavar='', help="打开xlsx、xls、csv文件")

    example = parser.add_argument_group("example")
    example.add_argument(
        action='store_false',
        dest="-u , --url            python3 NAE.py -u -f test.xlsx    仅提取表格中的URL")
    example.add_argument(
        action='store_false',
        dest="-u , --url            python3 NAE.py --url --filename=test.xlsx    仅提取表格中的URL")
    example.add_argument(
        action='store_false',
        dest="-f , --filename       python3 NAE.py -f test.xlsx    提取表格中的URL、域名、IP")
    example.add_argument(
        action='store_false',
        dest="-f , --filename       python3 NAE.py --filename=test.xlsx    提取表格中的URL、域名、IP")

    return parser.parse_args()


def main():
    option = arguments()

    try:
        if option.url and option.filename:
            extracts = process_excel_datas(option.filename)
            url_matches(extracts)

        elif option.domain and option.filename:
            extracts = process_excel_datas(option.filename)
            domain_matches(extracts)

        elif option.ip and option.filename:
            extracts = process_excel_datas(option.filename)
            ip_matches(extracts)

        elif option.filename:
            extracts = process_excel_datas(option.filename)
            domain_matches(extracts)
            url_matches(extracts)
            ip_matches(extracts)

        else:
            print(f"命令不正确哦，请重新输入！")

    except Exception as e:
        error_message = str(e)
        print("报错语句如下：" + error_message + '\n')


if __name__ == '__main__':
    print_banners()
    main()


