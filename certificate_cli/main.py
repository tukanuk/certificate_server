# import argparse
from logging.config import dictConfig
from pathlib import Path
import ssl

import typer
from flask import Flask

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate, CertificateSigningRequest

from .pki_helpers import generate_private_key, generate_public_key, generate_csr, sign_csr


app = typer.Typer()

# Adjusted logging to get millisecond precision
dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://flask.logging.wsgi_errors_stream",
                "formatter": "default",
            }
        },
        "root": {"level": "INFO", "handlers": ["wsgi"]},
    }
)


flask_app = Flask(__name__)


@flask_app.route("/")
def index():
    return f"<p>Hello. Using key {prefix} on port {port} </p>"


@app.command()
def info(path:str):
    """
    Basic info of a pem certificate
    """

    cert_file_path = Path(path)
    if not cert_file_path.exists:
        print("There is no certificate at this path")
    else:
        with open(cert_file_path, 'rb') as cert_file:
            cert_data = cert_file.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Display the certificate details
    print(f"{'Subject:':>17} {cert.subject}")
    print(f"{'Issuer:':>17} {cert.issuer}")
    print(f"{'Serial Number:':>17} {cert.serial_number}")
    print(f"{'Not Before:':>17} {cert.not_valid_before_utc}")
    print(f"{'Not After:':>17} {cert.not_valid_after_utc}")
    print(f"{'Public Key:':>17} {cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")

@app.command()
def generate(days:int = 30, prefix:str = "", path:str = "./certs"):
    """
    Generate a SSL certificate
    """

    directory_path = Path(path)
    if not directory_path.exists():
        directory_path.mkdir(parents=True, exist_ok=True)
        print(f"{path} was created.")

    if prefix != "":
        prefix = prefix + "-"

    # === ACTING AS THE CA ===
    # 1 Generate the CA private key
    ca_private_key: RSAPrivateKey = generate_private_key(
        f"{path}/ca-{prefix}private-key.pem", 
        "password"
        )
    print(f"🔑 CA Private: {ca_private_key}")

    # Generate the CA public key
    ca_public_key: Certificate = generate_public_key(
        private_key=ca_private_key,
        filename=f"{path}/ca-{prefix}public-key.pem",
        days=days,
        country="CA",
        state="Ontario",
        locality="Windsor",
        org="My Org",
        hostname="single-san.net",
        )
    print(f"🔑 CA Public: {ca_public_key}")

    # 2 Generate the server private key
    server_private_key: RSAPrivateKey = generate_private_key(
        f"{path}/server-{prefix}private-key.pem",
        "password"
        )
    print(f"🔑 Server Private: {server_private_key}")

    # 3 Generate the  Certificate Signing Request (CSR)
    csr: CertificateSigningRequest = generate_csr(
        private_key=server_private_key,
        filename=f"{path}/server-{prefix}csr.pem",
        country="CA",
        state="Ontario",
        locality="Windsor",
        org="My Org",
        alt_names=["single-san.net"],
        hostname="single-san.net",
    )
    print(f"📄 Certifcate Signing Request: {csr}")


    # 4 Sign the CSR with both the CA Private and Public keys
    # This produces a signed CSR that is verified by a CA
    # In this case, the CA is the same person, hence self-signed

    server_public_key= sign_csr(csr, ca_public_key, ca_private_key, f"{path}/server-{prefix}public-key.pem", days)

    print(f"🔑 Server Public: {server_public_key}")

@app.command()
def simulate(public: str, private: str, port: int = 5678):
    """
    Provide a path to public and private certificates.

    Use --port to specify a port to serve the certificat on.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile=public, keyfile=private)
    flask_app.run(port=port, debug=True, ssl_context=context)

def start_cli():
    app()

if __name__ == "__main__":

    app()
