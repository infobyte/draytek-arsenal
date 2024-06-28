import requests
from draytek_arsenal.commands.base import Command
from typing import Any, Dict, List
from base64 import b64encode

class SendToCgi(Command):

    @staticmethod
    def name() -> str:
        return "send_to_cgi"

    @staticmethod
    def description() -> str:
        return "Send a file to the CGI of the router.\n" + \
            "It could be used to upload a new DLM or something to the file system"

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["ip"], "kwargs": {"type": str, "help": "IP of the router"}},
            {"flags": ["file"], "kwargs": {"type": str, "help": "Path to the file to send"}},
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
        router_url = base_url + 'cfgrest.cgi?sFormAuthStr='
        auth_str = 'authstr'
        session_cookie = resp.cookies['SESSION_ID_VIGOR']

        with open(args.file, 'rb') as f:
            cookies = {'SESSION_ID_VIGOR': session_cookie}
            res = requests.post(router_url + auth_str, cookies = cookies, files = {args.file: f})

            if res.ok:
                print(f"[+] Successfully written file '{args.file}'")

            else:
                print("[x] Received an error response")
