import subprocess
from sword.utils.output import error
from sword.network_modular.host import Host
from sword.network_modular.get_network_info_modular import get_ifaces

#up: sudo tc qdisc add dev wlan0 root netem delay 2000ms
#down: sudo tc qdisc del dev wlan0 root netem delay 2000ms
def _shell(command):
    return subprocess.call('sudo ' + command)

try:
    _BIN_TC = subprocess.check_output('sudo which tc', shell=True).decode('utf-8')

except subprocess.CalledProcessError:
    error('can not find tc.')
    error('can not use limit modular.')


class Limit(object):
    def __init__(self) -> None:
        self._iface = get_ifaces()
        self._shell = _shell

    def limit(self, host: Host, delay):
        pass