import ssl
import json
import argparse
from time import sleep
from base64 import b64encode
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter, PoolManager
from requests.packages import urllib3
import rsa

urllib3.disable_warnings()


class TLSv1_2HttpAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.options = ssl.PROTOCOL_TLS & ssl.OP_NO_TLSv1_3
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ssl_context)


@dataclass
class WifiNetwork:
    ssid: str
    wpa_auth: int
    wpa_cipher: int


class GAApi:
    def __init__(self, ip=None):
        self.s = requests.Session()
        self.s.verify = False
        self.s.timeout = 5
        self.s.mount('https://', TLSv1_2HttpAdapter())

        if not ip:
            ip = "192.168.255.249"
            print(f"No IP informed, using default {ip}")
        self.CHROMECAST_HOST = f"https://{ip}:8443"

    def _request_endpoint(self, obj):
        try:
            request_ = obj
        except requests.exceptions.ConnectTimeout as a:
            print(f"Connection to Chromecast timed out: {a}")
        except Exception as a:
            print(a)
        else:
            return request_

    def scan_wifi(self, ssid=None):
        r = self._request_endpoint(
            self.s.post(f"{self.CHROMECAST_HOST}/setup/scan_wifi"))
        print("Scanning networks...")
        sleep(10)
        r = self.s.get(f"{self.CHROMECAST_HOST}/setup/scan_results")
        for i in r.json():
            if 'ssid' in i and i['ssid'] == ssid:
                return WifiNetwork(ssid, i['wpa_auth'], i['wpa_cipher'])
        else:
            return [WifiNetwork(i['ssid'], i['wpa_auth'], i['wpa_cipher'])
                    for i in r.json()]

    def get_info(self) -> dict:
        r = self._request_endpoint(
            self.s.get(f"{self.CHROMECAST_HOST}/setup/eureka_info"))
        return r.json()

    def list_networks(self) -> dict:
        r = self._request_endpoint(
            self.s.get(f"{self.CHROMECAST_HOST}/setup/configured_networks"))
        return r.json()

    def forget_network(self, id_: int) -> dict:
        r = self._request_endpoint(
            self.s.post(
                f"{self.CHROMECAST_HOST}/setup/forget_wifi",
                json={
                    "wpa_id": id_
                }))
        return r

    def connect_wifi(
            self,
            wifi,
            password=None):
        r = self.get_info()
        public_key = ("-----BEGIN RSA PUBLIC KEY-----\n"
                      + r["public_key"]
                      + "\n-----END RSA PUBLIC KEY-----")
        rsa_key = rsa.PublicKey.load_pkcs1(public_key)

        connect_command = {
            "ssid": wifi.ssid,
            "wpa_auth": wifi.wpa_auth,
            "wpa_cipher": wifi.wpa_cipher,
            "enc_passwd": b64encode(
                rsa.encrypt(password.encode(), rsa_key)).decode()}

        r = self.s.post(
            f"{self.CHROMECAST_HOST}/setup/connect_wifi", json=connect_command)

        sleep(2)

        r = self.s.post(
            f"{self.CHROMECAST_HOST}/setup/save_wifi",
            json={"keep_hotspot_until_connected": True})
        return r.text

    def set_name(self, name: str) -> str:
        r = self.s.post(
            f"{self.CHROMECAST_HOST}/setup/save_wifi",
            json={
                "name": name,
                "opt_in": {
                    "crash": False,
                    "stats": False,
                    "opencast": False
                }
            })
        return r.text


def main():
    parser = argparse.ArgumentParser(
        prog='setupchromecast',
        description='Setup Chromecast device without Google Home app')
    parser.add_argument(
        '--ip',
        default=False,
        help='IP of the device')
    parser.add_argument(
        '--connect',
        action='store_true',
        default=None,
        help='Connect to a new network')
    parser.add_argument(
        '--name',
        default=None,
        help='Change the Chromecast device name')
    parser.add_argument(
        '--list',
        action='store_true',
        default=False,
        help='List configured networks')
    parser.add_argument(
        '--forget',
        action='store_true',
        default=False,
        help='Forget configured network')
    parser.add_argument(
        '--info',
        action='store_true',
        default=False,
        help='Get device info')

    args = parser.parse_args()

    a = GAApi(ip=args.ip)

    if args.connect:
        networks = {str(x): y for x, y in enumerate(a.scan_wifi())}
        for i in networks.items():
            print(f"ID {i[0]}: {i[1].ssid}")
        id_ = input("Select ID of the network to connect: ")
        passwd = input("Wifi password: ")
        print(a.connect_wifi(wifi=networks.get(id_), password=passwd))

    if args.name:
        print(a.set_name(args.name))

    if args.forget:
        for i in a.list_networks():
            print(f"ID {i['wpa_id']}: {i['ssid']}")
        id_ = input("Select ID of the network to forget: ")
        print(a.forget_network(int(id_)))

    if args.list:
        print(
            "\n".join(
                [f"ID {i['wpa_id']}: {i['ssid']}"
                 for i in a.list_networks()]))

    if args.info:
        print(json.dumps(a.get_info(), indent=4))


if __name__ == "__main__":
    main()
