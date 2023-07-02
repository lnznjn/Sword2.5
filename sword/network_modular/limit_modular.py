import os
import subprocess
import threading

from sword.utils.output import error, text
from sword.network_modular.host import Host
from sword.network_modular.get_network_info_modular import get_ifaces

#up: sudo tc qdisc add dev wlan0 root netem delay 2000ms
#down: sudo tc qdisc del dev wlan0 root netem delay 2000ms

#sudo tc class add dev wlan0 parent 1:0 classid 1:1 htb rate 1kbit
#sudo tc filter add dev wlan0 parent 1:0 protocol ip prio 1 handle 1 fw flowid 1:1
#sudo iptable -A POSTROUTING -s 192.168.2.23 -j MARK --set-mark 1



def _shell(command):
    os.system(command)




class Limit(object):
    def __init__(self) -> None:
        self._IF_FOUND = True

        try:
            self._BIN_TC = subprocess.check_output('sudo which tc', shell=True).decode('utf-8').replace('\n', '')
            self._BIN_IPTABLES = subprocess.check_output('sudo which iptables', shell=True).decode('utf-8').replace('\n', '')

        except subprocess.CalledProcessError:
            error('can not find tc or iptables.')
            error('can not use limit modular.')
            self._IF_FOUND = False
        
        self._hosts_lock = threading.Lock()
        self._limited_hosts = set()
        
        self._iface = get_ifaces()
        self._shell = _shell
        self._rate = '10kbit' #you can change this value to control target traffic.
        
        self._shell(f'{self._BIN_TC} qdisc add dev {self._iface} root handle 1:0 htb')
    
    def limit(self, host: Host):
        host.limit = True
        
        with self._hosts_lock:
            self._limited_hosts.add(host)
        
        ip = host.ip
        id = int(host.num) + 1

        if not self._IF_FOUND:
            error('can not find tc or iptables.')
            error('can not use limit modular.')
            return

        self._shell(f'{self._BIN_TC} class add dev {self._iface} parent 1:0 classid 1:{id} htb rate {self._rate}')
        self._shell(f'{self._BIN_TC} filter add dev {self._iface} parent 1:0 protocol ip prio {id} handle {id} fw flowid 1:{id}')
        self._shell(f'{self._BIN_IPTABLES} -t mangle -A POSTROUTING -s {ip} -j MARK --set-mark {id}')
        self._shell(f'{self._BIN_IPTABLES} -t mangle -A PREROUTING -d {ip} -j MARK --set-mark {id}')

    def unlimit(self, host: Host):
        host.limit = False
        
        with self._hosts_lock:
            self._limited_hosts.discard(host)
        
        ip = host.ip
        id = int(host.num) + 1
        
        if not self._IF_FOUND:
            error('can not find tc or iptables.')
            error('can not use limit modular.')
            return
        
        self._shell(f'{self._BIN_TC} filter del dev {self._iface} parent 1:0 prio {id}')
        self._shell(f'{self._BIN_TC} class del dev {self._iface} parent 1:0 classid 1:{id}')
        self._shell(f'{self._BIN_IPTABLES} -t mangle -D POSTROUTING -s {ip} -j MARK --set-mark {id}')
        self._shell(f'{self._BIN_IPTABLES} -t mangle -D PREROUTING -d {ip} -j MARK --set-mark {id}')

    def clear(self):
        self._shell(f'{self._BIN_TC} filter del dev {self._iface} parent 1:0')
        self._shell(f'{self._BIN_TC} class del dev {self._iface} parent 1:0')
        self._shell(f'{self._BIN_IPTABLES} -F')
        self._shell(f'{self._BIN_IPTABLES} -X')