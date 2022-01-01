import base64
import json
import random
import uuid

import httpx
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class Dnslog:
    def __init__(self):
        self._client = httpx.Client()
        req = self._client.get("http://www.dnslog.cn/getdomain.php", timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self._client.get("http://www.dnslog.cn/getrecords.php", timeout=30)
        return req.json()


class Interactsh:
    # Source: https://github.com/fullhunt/log4j-scan/blob/7be0f1c02ce3494469dc73a177e6f0c96f0016d9/log4j-scan.py#L163
    def __init__(self, token="", server=""):
        # Source: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = server.lstrip('.') or 'interact.sh'
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid.uuid4())
        self.encoded = base64.b64encode(self.public_key).decode("utf8")
        guid = uuid.uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.client = httpx.Client()
        self.client.headers = self.headers
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.client.post(
            f"https://{self.server}/register", headers=self.headers, json=data, timeout=30)
        if 'success' not in res.text:
            raise RuntimeError("Can not initiate interact.sh DNS callback client")

    def pull_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.client.get(url, headers=self.headers, timeout=30).json()
        aes_key, data_list = res['aes_key'], res['data']
        for i in data_list:
            decrypt_data = self.__decrypt_data(aes_key, i)
            result.append(self.__parse_log(decrypt_data))
        return result

    def __decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        blocksize = AES.block_size
        initialisation_vector = decode[:blocksize]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=initialisation_vector, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def __parse_log(self, log_entry):
        new_log_entry = {"timestamp": log_entry["timestamp"],
                         "host": f'{log_entry["full-id"]}.{self.domain}',
                         "remote_address": log_entry["remote-address"]
                         }
        return new_log_entry
