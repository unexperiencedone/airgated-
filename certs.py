"""Persistent TLS material for the captive portal.

The CA and server certificate are generated once and reused across restarts (Finding 4.7), so a
student who trusted the classroom CA -- or clicked through the warning -- keeps that trust after
the host laptop reboots. The server certificate is only reissued when it is missing, close to
expiry, or no longer covers the configured hotspot IP.
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CA_CERT_FILE = "ca.crt"
CA_KEY_FILE = "ca.key"
SERVER_CERT_FILE = "server.crt"
SERVER_KEY_FILE = "server.key"

# iOS/macOS refuse to trust TLS server certificates valid for longer than 825 days.
SERVER_CERT_DAYS = 825
CA_CERT_DAYS = 3650
RENEW_BEFORE_DAYS = 30


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _write_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))


def _write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _create_ca(ssl_dir):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AirGated Classroom CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=CA_CERT_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_key(os.path.join(ssl_dir, CA_KEY_FILE), key)
    _write_cert(os.path.join(ssl_dir, CA_CERT_FILE), cert)
    return cert, key


def _create_server_cert(ssl_dir, ca_cert, ca_key, local_ip):
    key = ec.generate_private_key(ec.SECP256R1())
    san = x509.SubjectAlternativeName([
        x509.IPAddress(ipaddress.ip_address(local_ip)),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.DNSName("localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, local_ip)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=SERVER_CERT_DAYS))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(os.path.join(ssl_dir, SERVER_KEY_FILE), key)
    _write_cert(os.path.join(ssl_dir, SERVER_CERT_FILE), cert)
    return cert


def _server_cert_usable(cert, local_ip):
    if cert.not_valid_after_utc - _now() < datetime.timedelta(days=RENEW_BEFORE_DAYS):
        return False
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    return ipaddress.ip_address(local_ip) in san.get_values_for_type(x509.IPAddress)


def ensure_certs(ssl_dir, local_ip):
    """Return (cert_path, key_path, ca_path), creating only what is missing or stale."""
    os.makedirs(ssl_dir, exist_ok=True)
    ca_path = os.path.join(ssl_dir, CA_CERT_FILE)
    ca_key_path = os.path.join(ssl_dir, CA_KEY_FILE)
    cert_path = os.path.join(ssl_dir, SERVER_CERT_FILE)
    key_path = os.path.join(ssl_dir, SERVER_KEY_FILE)

    if os.path.exists(ca_path) and os.path.exists(ca_key_path):
        ca_cert, ca_key = _load_cert(ca_path), _load_key(ca_key_path)
        created = False
    else:
        ca_cert, ca_key = _create_ca(ssl_dir)
        created = True

    reuse = (
        not created
        and os.path.exists(cert_path)
        and os.path.exists(key_path)
        and _server_cert_usable(_load_cert(cert_path), local_ip)
    )
    if not reuse:
        _create_server_cert(ssl_dir, ca_cert, ca_key, local_ip)
    return cert_path, key_path, ca_path, reuse
