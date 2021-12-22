import argparse
import base64
import json
import logging
import random
import uuid
from time import sleep

from log4j_scanner.scanners import HttpScanner, SmtpScanner, ImapScanner, SshScanner, RawSocketScanner

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


LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "error": logging.ERROR,
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("A scanner to check for the log4j vulnerability")

    target_opts = parser.add_mutually_exclusive_group(required=True)
    target_opts.add_argument('-t', '--target', help="The target to check", type=str, action="store", default=None)
    target_opts.add_argument('--target-list', help="The target to check", type=str, action="store", default=None)

    parser.add_argument('-p', '--protocol', help="which protocol to test", choices=["http", "ssh", "imap", "smtp", "socket"], default="http", type=str)
    parser.add_argument('-o', '--obfuscate', help="Whether payloads should be obfuscated or not", default=False, action="store_true")
    parser.add_argument('--certificate-path', help="Path to a client certificate for mTLS or SSH.", type=str, action="store", default=None)
    parser.add_argument('--no-payload-domain', help="Whether the original domain should be removed from the payload", default=False, action="store_true")
    parser.add_argument('--request-path', help="A custom path to add to the requests", type=str, default=None, action="store")
    parser.add_argument('-l', '--log-level', help="How detailed logging should be.", choices=LOG_LEVELS.keys(), default="info")
    parser.add_argument('--use-localhost-bypass', help="Will use the bypass of CVE-2021-45046 in the payloads.", action="store_true", default=False)

    http_opts = parser.add_argument_group("HTTP Options")
    http_opts.add_argument('--proxy', help="A proxy URL", type=str, default=None)
    http_opts.add_argument('--generate-clientcert', help="Generates a client certificate.", action="store_true", default=False)
    http_opts.add_argument('--all-in-one', help="Test all headers in one iteration", action="store_true", default=False)

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
        scanner = HttpScanner(
            arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass,
            arguments.certificate_path, arguments.proxy, arguments.generate_clientcert, arguments.all_in_one
        )
    elif arguments.protocol == "ssh":
        scanner = SshScanner(arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass, arguments.certificate_path)
    elif arguments.protocol == "imap":
        scanner = ImapScanner(arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass)
    elif arguments.protocol == "smtp":
        scanner = SmtpScanner(arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass, arguments.local_hostname)
    elif arguments.protocol == "socket":
        scanner = RawSocketScanner(arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass)

    if arguments.target_list:
        with open(arguments.target_list, 'r') as targets:
            for target in targets.readlines():
                if target[:4] != "http" and arguments.protocol == "http":
                    scan_target = f"http://{target}/"
                else:
                    scan_target = target
                scanner.run_tests(
                    scan_target, callback_domain, not arguments.no_payload_domain, use_random_request_path
                )
    else:
        if arguments.target[:4] != "http" and arguments.protocol == "http":
            scan_target = f"http://{arguments.target}/"
        else:
            scan_target = arguments.target
        scanner.run_tests(
            scan_target, callback_domain, not arguments.no_payload_domain, use_random_request_path
        )

    if not dns_callback:
        return

    sleep(10)
    records = dns_callback.pull_logs()
    if records:
        logging.info(f"Results: {records}")
        print(records)
    else:
        logging.info("No results found")
    logging.info(f"Please keep checking {dns_callback.domain}.")


if __name__ == "__main__":
    main()
