# coding: utf-8

import socket
from random import randrange
import time
import select
import xmltodict
import re
import requests
from urllib.parse import urlparse

def parse_device(url, name, field='modelName'):
    r = requests.get(url)
    xml = xmltodict.parse(r.text)['root']
    if re.search(name, xml['device'][field]):
        return urlparse(url).hostname, xml['device']['friendlyName']

def scan(st, timeout):
    timeout_epoch = int(time.time()) + timeout
    src_port = randrange(51100, 51200)
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(('', src_port))
    
    MCAST_GRP, MCAST_PORT = '239.255.255.250', 1900
    ecp = ("M-SEARCH * HTTP/1.1\r\n"
           f"HOST: {MCAST_GRP}:{MCAST_PORT}\r\n"
           "MX: 1\r\n"
           'MAN: "ssdp:discover"\r\n'
           f"ST: {st}\r\n\r\n")
    
    usock.setblocking(0)
    usock.sendto(ecp.encode(), (MCAST_GRP, MCAST_PORT))
    
    devices = []
    while int(time.time()) < timeout_epoch:
        time.sleep(0.25)
        ready = select.select([usock], [], [], timeout)
        if ready[0]:
            devices.append(usock.recv(1024).decode("ascii"))
    
    usock.close()
    return devices

def get_devices(
        st="urn:dial-multiscreen-org:device:dial:1",
        field='modelName',
        name='Eureka Dongle',
        timeout=5):
    prog = re.compile(r"LOCATION: (.+)\r\n")
    return [parse_device(prog.search(i).group(1), name, field)
            for i in scan(st, timeout)]

if __name__ == "__main__":
    print(get_devices())
