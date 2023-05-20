import socket
import netifaces
from sword.utils.output import error

def get_local_host():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_host = s.getsockname()[0]
        return local_host

    except:
        error("Socket error.")
        return None

    finally:
        s.close()

def get_ifaces():
    try:
        default = netifaces.gateways()['default'][2]
        return default[1]
    except:
        error('Can not get default.')
        exit(1)

def get_gateway():
    try:
        default = netifaces.gateways()['default'][2]
        return default[0]
    except:
        error('Can not get default.')
        exit(1)

if __name__ == '__main__':
    ifaces = get_ifaces()
    gateway_ip = get_gateway()
    print(ifaces)
    print(gateway_ip)

