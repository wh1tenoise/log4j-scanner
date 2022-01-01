import random
import string
from OpenSSL import crypto
from Crypto.PublicKey import RSA


def create_openssh_key(
    keysize=2048,
    path_to_privatekey="injection",
    path_to_certificate="injection.pub"
):
    key = RSA.generate(keysize)
    with open(path_to_privatekey, 'wb') as content_file:
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(path_to_certificate, 'wb') as content_file:
        content_file.write(pubkey.exportKey('OpenSSH'))


def generate_client_cert(
    emailAddress="emailAddress",
    commonName="commonName",
    countryName="NT",
    localityName="localityName",
    stateOrProvinceName="stateOrProvinceName",
    organizationName="organizationName",
    organizationUnitName="organizationUnitName",
    subjectAltName: list[str] = ["DNS:subjectAltName"],
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10 * 365 * 24 * 60 * 60,  # 10 years
    path_to_certificate="injection.pem"
):
    # can look at generated file using openssl:
    # openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    subject = cert.get_subject()
    subject.C = countryName
    subject.ST = stateOrProvinceName
    subject.L = localityName
    subject.O = organizationName
    subject.OU = organizationUnitName
    subject.CN = commonName
    subject.emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(validityStartInSeconds)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.add_extensions(
        [
            crypto.X509Extension(b"subjectAltName", False, ','.join(subjectAltName).encode()),
            crypto.X509Extension(b'extendedKeyUsage', False, b'clientAuth'),
        ]
    )
    cert.set_issuer(subject)
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(path_to_certificate, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
        return f.name


def obfuscate_lower(c: str) -> str:
    return f"${{lower:{c}}}"


def obfuscate_upper(c: str) -> str:
    return f"${{upper:{c}}}"


def obfuscate_dash(c: str) -> str:
    payloads = []
    for _ in range(random.randint(1, 5)):
        payloads.append(
            ''.join(
                random.choice(
                    string.ascii_lowercase
                ) for _ in range(
                    random.randint(1, 6)
                )
            )
        )
    return f"${{{':'.join(payloads)}:-{c}}}"


if __name__ == "__main__":
    generate_client_cert()
