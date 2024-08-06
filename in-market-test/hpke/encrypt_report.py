# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

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
        data = IPAReportInfo.DOMAIN.encode('utf-8') + b'\x00' + self.helper_domain.encode('utf-8') + b'\x00' + self.site_domain.encode('utf-8') + b'\x00' + self.key_id.to_bytes() + self.epoch.to_bytes(2) + self.event_type.to_bytes()
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
        return self.info.event_type.to_bytes(1) + self.info.key_id.to_bytes(1) + self.info.epoch.to_bytes(2) + self.info.site_domain.encode('utf-8')

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
    # code to be executed when the program is run
    public_key = "92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a"
    helper_domain="github.com/private-attribution"
    encrypted_match_key="2d9bc24772352055463a044d257299a64bf586fd79558da6668533ac0a824266d4522d15fcebd04779ad360c9ddca0b7f8c5aca263928319bf6904c765807e69"
    share_data=b'\x01\x02\x03\x01\x02\x03\x01\x01\x01\x01'
    site_domain="www.meta.com"
    encrypted_data = encrypt_share(share_data, 0, site_domain, public_key, helper_domain)

    print(len(encrypted_data.encrypted_to_bytes()))
    print(len(encrypted_data.ipa_report_info_to_bytes()))
    print(f"{encrypted_match_key}{encrypted_data.encrypted_to_bytes().hex()}{encrypted_data.ipa_report_info_to_bytes().hex()}")


if __name__ == "__main__":
    main()