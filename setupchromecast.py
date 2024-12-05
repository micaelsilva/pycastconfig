import ssl
import json
from time import sleep
from base64 import b64encode

import requests
from requests.adapters import HTTPAdapter, PoolManager
from requests.packages import urllib3

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

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


class GAApi:
    def __init__(self, ip: str = "192.168.255.249"):
        self.s = requests.Session()
        self.s.verify = False
        self.s.timeout = 5
        self.s.mount('https://', TLSv1_2HttpAdapter())

        self.CHROMECAST_HOST = f"https://{ip}:8443"

    def scan_wifi(self, ssid=False):
        r = self._request_endpoint(
            self.s.post(f"{self.CHROMECAST_HOST}/setup/scan_wifi"))
        print(r.text)
        sleep(10)
        r = self.s.get(f"{self.CHROMECAST_HOST}/setup/scan_results")
        for i in r.json():
            if 'ssid' in i and i['ssid'] == ssid:
                wpa_auth, wpa_cipher = i['wpa_auth'], i['wpa_cipher']
                return [ssid, wpa_auth, wpa_cipher]
        else:
            return {x["ssid"] for x in r.json()}

    def _request_endpoint(self, obj):
        try:
            request_ = obj
        except requests.exceptions.ConnectTimeout as a:
            print(f"Connection to Chromecast timed out: {a}")
        except Exception as a:
            print(a)
        else:
            return request_

    def get_info(self):
        r = self._request_endpoint(
            self.s.get(f"{self.CHROMECAST_HOST}/setup/eureka_info"))
        return json.dumps(r.json(), indent=4)

    def connect_wifi(
            self,
            ssid,
            password=None,
            wpa_auth=None,
            wpa_cipher=None):
        r = self._request_endpoint(
            self.s.get(f"{self.CHROMECAST_HOST}/setup/eureka_info"))
        public_key = r.json()["public_key"]

        public_key = f"-----BEGIN RSA PUBLIC KEY-----\n{public_key}\n-----END RSA PUBLIC KEY-----"
        rsa_key = RSA.importKey(public_key)
        cipher = PKCS1_v1_5.new(rsa_key)

        connect_command = {
            "ssid": ssid,
            "wpa_auth": wpa_auth,
            "wpa_cipher": wpa_cipher,
            "enc_passwd": b64encode(cipher.encrypt(password.encode()))}

        r = self.s.post(
            f"{self.CHROMECAST_HOST}/setup/connect_wifi", json=connect_command)
        print(r.text)

        sleep(2)

        r = self.s.post(
            f"{self.CHROMECAST_HOST}/setup/save_wifi",
            json={"keep_hotspot_until_connected": True})
        print(r.text)

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


if __name__ == "__main__":
    a = GAApi(ip="10.0.0.73")
    print(a.scan_wifi())
