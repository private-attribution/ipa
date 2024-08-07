import argparse
import pyhpke
from cryptography.hazmat.primitives.asymmetric import x25519

class IPAReportInfo:
    DOMAIN = "private-attribution"

    def __init__(
        self,
        key_id: int,
        epoch: int,
        event_type: int,
        helper_domain: str,
        site_domain: str,
    ):
        self.key_id = key_id
        self.epoch = epoch
        self.event_type = event_type
        self.helper_domain = helper_domain
        self.site_domain = site_domain

    def __str__(self):
        return f"key_id: {self.key_id}, epoch: {self.epoch}, event_type: {self.event_type}, helper_domain: {self.helper_domain}, site_domain: {self.site_domain}"

    def to_bytes(self):
        data = IPAReportInfo.DOMAIN.encode('utf-8') + b'\x00' + self.helper_domain.encode('utf-8') + b'\x00' + self.site_domain.encode('utf-8') + b'\x00' + self.key_id.to_bytes(1, 'little') + self.epoch.to_bytes(2, 'little') + self.event_type.to_bytes(1, 'little')
        return data       

class IPAKeyEncryption:
    def __init__(
        self,
        encapsulated_key: bytes,
        ciphertext_and_tag: bytes,
        info: IPAReportInfo,
    ):
        self.encapsulated_key = encapsulated_key
        self.ciphertext_and_tag = ciphertext_and_tag
        self.info = info

    def __str__(self):
        return f"encapsulated_key: {self.encapsulated_key}, ciphertext_and_tag: {self.ciphertext_and_tag}, info: {self.info}"

    def encrypted_to_bytes(self):
        return self.encapsulated_key + self.ciphertext_and_tag
    
    def ipa_report_info_to_bytes(self):
        return self.info.event_type.to_bytes(1, 'little') + self.info.key_id.to_bytes(1, 'little') + self.info.epoch.to_bytes(2, 'little') + self.info.site_domain.encode('utf-8')

def encrypt_share(
    share_data: bytes,
    event_type: int,
    site_domain: str,
    public_key_string: str,
    helper_domain: str,
):
    raw_public_key = bytes.fromhex(public_key_string)
    pyca_public_key = x25519.X25519PublicKey.from_public_bytes(raw_public_key)
    public_key = pyhpke.KEMKey.from_pyca_cryptography_key(pyca_public_key)

    ciphersuite = pyhpke.CipherSuite.new(
        kem_id=pyhpke.KEMId.DHKEM_X25519_HKDF_SHA256,
        kdf_id=pyhpke.KDFId.HKDF_SHA256,
        aead_id=pyhpke.AEADId.AES128_GCM,
    )
    report_info_data = IPAReportInfo(
        key_id=0,
        epoch=0,
        event_type=event_type,
        helper_domain=helper_domain,
        site_domain=site_domain,
    )

    encapsulated_key, sender = ciphersuite.create_sender_context(
        pkr=public_key, info=report_info_data.to_bytes()
    )
    ciphertext_and_tag = sender.seal(share_data)

    return IPAKeyEncryption(
        encapsulated_key=encapsulated_key,
        ciphertext_and_tag=ciphertext_and_tag,
        info=report_info_data,
    )

def main():
    parser = argparse.ArgumentParser(description="Sample function for encrypting shared data for IPA query")
    parser.add_argument("--pub_key", required=True, help="The public key used for encryption")
    parser.add_argument("--helper_domain", required=False, default="github.com/private-attribution", help="IPA helper domain, defaults to github.com/private-attribution")
    parser.add_argument("--site_domain", required=True, help="The site domain where the event originates from")
    parser.add_argument("--event", required=False, type=int, default=0, help="Event type. 0 for source event, 1 for trigger event")
    parser.add_argument("data", help="Data to be encrypted")

    args = parser.parse_args()
    encrypted_data = encrypt_share(args.data.encode('utf-8'), args.event, args.site_domain, args.pub_key, args.helper_domain)

    print(f"{encrypted_data.encrypted_to_bytes().hex()}{encrypted_data.ipa_report_info_to_bytes().hex()}")


if __name__ == "__main__":
    main()