import argparse
import logging
from time import sleep

from log4j_scanner.callbacks import Dnslog, Interactsh
from log4j_scanner.scanners import (FtpScanner, HttpScanner, ImapScanner, PostgresScanner,
                                    RawSocketScanner, SmtpScanner, SshScanner)

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

    parser.add_argument('-p', '--protocol', help="which protocol to test", choices=["http", "ssh", "imap", "smtp", "socket", "ftp", "postgres"], default="http", type=str)
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

    scan_targets = []
    if arguments.target_list:
        with open(arguments.target_list, 'r') as targets:
            for target in targets.readlines():
                if target[:4] != "http" and arguments.protocol == "http":
                    scan_target = f"http://{target}/"
                else:
                    scan_target = target
                scan_targets.append(scan_target)
    else:
        if arguments.target[:4] != "http" and arguments.protocol == "http":
            scan_target = f"http://{arguments.target}/"
        else:
            scan_target = arguments.target
        scan_targets.append(scan_target)

    if arguments.protocol == "http":
        scanner = HttpScanner(
            scan_targets,
            arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass,
            arguments.certificate_path, arguments.proxy, arguments.generate_clientcert, arguments.all_in_one
        )
    elif arguments.protocol == "ssh":
        scanner = SshScanner(scan_targets, arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass, arguments.certificate_path)
    elif arguments.protocol == "imap":
        scanner = ImapScanner(scan_targets, arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass)
    elif arguments.protocol == "smtp":
        scanner = SmtpScanner(scan_targets, arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass, arguments.local_hostname)
    elif arguments.protocol == "socket":
        scanner = RawSocketScanner(scan_targets, arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass)
    elif arguments.protocol == "ftp":
        scanner = FtpScanner(scan_targets, arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass)
    elif arguments.protocol == "postgres":
        scanner = PostgresScanner(scan_targets, arguments.obfuscate, arguments.request_path, arguments.use_localhost_bypass)

    scanner.run_tests(
        callback_domain, not arguments.no_payload_domain, use_random_request_path
    )

    if not dns_callback:
        logging.info("Keep monitoring your callback for interactions.")
        return

    count = 0
    records = []
    sleep_time = 10
    while count < 3 and not records:
        logging.info(f"Try #{count + 1} of getting records... Sleeping for {sleep_time}s")
        sleep(sleep_time)
        records = dns_callback.pull_logs()
        count += 1
    if records:
        logging.info(f"Results: {records}")
        print(records)
    else:
        logging.info("No results found")


main()
