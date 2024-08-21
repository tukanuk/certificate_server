# Generating a self-signed certificate
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, KeySerializationEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509 import (
    NameOID,
    Name,
    Certificate,
    CertificateBuilder,
    SubjectAlternativeName,
    CertificateSigningRequestBuilder,
    CertificateSigningRequest,
    )
from cryptography.hazmat.primitives import hashes

def generate_private_key(filename: str, passphrase: str) -> RSAPrivateKey:
    """ Step 1: Generate a private key 
    
        Return: a private key object (RSAPrivateKey)"""

    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend
    )

    utf8_pass: bytes = passphrase.encode('utf-8')
    algorithm: KeySerializationEncryption = serialization.BestAvailableEncryption(utf8_pass)
    algorithm_np = serialization.NoEncryption()

    with open(filename, "wb") as keyfile:
        keyfile.write(
            private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format= serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=algorithm_np
            )
        )

    return private_key

def generate_public_key(private_key:RSAPrivateKey, filename:str, days:int, **kwargs) -> Certificate:
    """ Step 2: Generate a self-signed public key using the private 
        key from step 1 as a starting point """
    
    subject: Name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs['country']),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]
            ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs['locality']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs['org']),
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs['hostname']),
        ]
    )

    # Because this is self signed, the issuer is always the subject
    issuer: Name = subject

    # This certificate is valid from now until 30 days
    valid_from: datetime = datetime.utcnow()
    valid_to: datetime = valid_from + timedelta(days=days)

    # Used to build the certifiate
    builder: CertificateBuilder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=True,
            path_length=None), critical=True)
    )

    # Sign the cerificate with the private key
    public_key: Certificate = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    with open(filename, "wb") as certfile:
        certfile.write(public_key.public_bytes(serialization.Encoding.PEM))
    
    return public_key

# Step 1 and 2 Generating Private and Public keys 
# with these keys we can act as a Certificate Authority (self-sign)

def generate_csr(private_key, filename, **kwargs) -> CertificateSigningRequest:
    """ Step 3: Generate Certificate Signing Authority 
        This is like a visa application
    
        Return: CertificateSigningRequest"""

    subject: Name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs['country']),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]
            ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs['locality']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs['org']),
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs['hostname']),
        ]
    )

    # Generate alt DNS names
    alt_names: list = []
    for name in kwargs.get("alt_names", []):
        alt_names.append(x509.DNSName(name))
    print(f"alt_names: {alt_names}")
    san: SubjectAlternativeName = x509.SubjectAlternativeName(alt_names)

    builder: CertificateSigningRequestBuilder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
    )

    csr: CertificateSigningRequest = builder.sign(private_key, hashes.SHA256(), default_backend)

    with open(filename, "wb") as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr

# With the CSR and the Server private key in hand (made by reusing step 1), 
# can now sign keys
# In real world, Certificate Authority would verifiy ownership of `org`

def sign_csr(csr, ca_public_key, ca_private_key, new_filename, days) -> Certificate:
    """ Step 4: Sign CSR
    Signs the certificate using the CA's private key. 
    
    Return: Signed Certificate
    """

    valid_from: datetime = datetime.utcnow()
    valid_until: datetime = valid_from + timedelta(days=days)

    builder: CertificateBuilder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_public_key.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
    )    

    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    
    public_key: Certificate = builder.sign(
        private_key= ca_private_key,
        algorithm= hashes.SHA256(),
        backend= default_backend(),
    )

    with open(new_filename, "wb") as keyfile:
        keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))

    return public_key

if __name__=="__main__":

    parser = argparse.ArgumentParser(description='',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--days', default=30, type=int, help='Days until expire')
    parser.add_argument('-p', '--prefix', default='', help='a prefix for file names to aid organization')
    args = parser.parse_args()

    print(args.days)
    print(args.prefix)

    if args.prefix != "":
        prefix:str= args.prefix + "-"
    else:
        prefix: str = ""

    # === ACTING AS THE CA ===
    # 1 Generate the CA private key
    ca_private_key: RSAPrivateKey = generate_private_key(
        f"certs/ca-{prefix}private-key.pem", 
        "password"
        )
    print(f"🔑 CA Private: {ca_private_key}")

    # Generate the CA public key
    ca_public_key: Certificate = generate_public_key(
        private_key=ca_private_key,
        filename=f"certs/ca-{prefix}public-key.pem",
        days=args.days,
        country="CA",
        state="Ontario",
        locality="Windsor",
        org="My Org",
        hostname="single-san.net",
        )
    print(f"🔑 CA Public: {ca_public_key}")

    # === ACTING AS THE WEBSITE/SERVER OWNER ===

    # 2 Generate the server private key
    server_private_key: RSAPrivateKey = generate_private_key(
        f"certs/server-{prefix}private-key.pem",
        "password"
        )
    print(f"🔑 Server Private: {server_private_key}")


    # 3 Generate the  Certificate Signing Request (CSR)
    csr: CertificateSigningRequest = generate_csr(
        private_key=server_private_key,
        filename=f"certs/server-{prefix}csr.pem",
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

    server_public_key= sign_csr(csr, ca_public_key, ca_private_key, f"certs/server-{prefix}public-key.pem", args.days)

    print(f"🔑 Server Public: {server_public_key}")
    
