import argparse
import math
import os
import secrets
from enum import Enum

import pyhpke
from cryptography.hazmat.primitives.asymmetric import x25519


class EventType(Enum):
    SOURCE = 0
    TRIGGER = 1

    def to_bytes(self):
        return self.value.to_bytes(1, "little")


class ShareType(Enum):
    MATCH_KEY = 0
    TIMESTAMP = 1
    BREAKDOWN = 2
    TRIGGER_VALUE = 3

    def bit_count(self) -> int:
        match self:
            case ShareType.MATCH_KEY:
                return 64
            case ShareType.TIMESTAMP:
                return 20
            case ShareType.BREAKDOWN:
                return 8
            case ShareType.TRIGGER_VALUE:
                return 3

        raise Exception("Invalid share type")

    def byte_count(self) -> int:
        return math.ceil(self.bit_count() / 8)


class IPAReportInfo:
    DOMAIN = "private-attribution"

    def __init__(
        self,
        key_id: int,
        epoch: int,
        event_type: EventType,
        helper_domain: str,
        site_domain: str,
    ):
        self.key_id = key_id
        self.epoch = epoch
        self.event_type = event_type
        self.helper_domain = helper_domain
        self.site_domain = site_domain

    def __str__(self):
        return (
            f"key_id: {self.key_id}, epoch: {self.epoch}, event_type: {self.event_type}"
            f", helper_domain: {self.helper_domain}, site_domain: {self.site_domain}"
        )

    def to_bytes(self):
        data = (
            IPAReportInfo.DOMAIN.encode("utf-8")
            + b"\x00"
            + self.helper_domain.encode("utf-8")
            + b"\x00"
            + self.site_domain.encode("utf-8")
            + b"\x00"
            + self.key_id.to_bytes(1, "little")
            + self.epoch.to_bytes(2, "little")
            + self.event_type.to_bytes()
        )
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
        return (
            f"encapsulated_key: {self.encapsulated_key}, ciphertext_and_tag: "
            f"{self.ciphertext_and_tag}, info: {self.info}"
        )

    def encrypted_to_bytes(self):
        return self.encapsulated_key + self.ciphertext_and_tag

    def ipa_report_info_to_bytes(self):
        return (
            self.info.event_type.to_bytes()
            + self.info.key_id.to_bytes(1, "little")
            + self.info.epoch.to_bytes(2, "little")
            + self.info.site_domain.encode("utf-8")
        )


def encrypt_share(
    share_data: bytes,
    event_type: EventType,
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


class IPAShare:
    __slots__ = ["left", "right"]

    def __init__(self, left: bytes, right: bytes) -> None:
        self.left: bytes = left
        self.right: bytes = right

    def to_bytes(self) -> bytes:
        return self.left + self.right

    def xor(a: bytes, b: bytes) -> bytes:
        _len = max(len(a), len(b))
        a_int = int.from_bytes(a, "little")
        b_int = int.from_bytes(b, "little")
        x = a_int ^ b_int
        return x.to_bytes(_len, "little")

    def generate_random_share(share_type: ShareType) -> bytes:
        length = share_type.byte_count()

        bit_length = share_type.bit_count()

        rand_int = secrets.randbelow(2**bit_length)
        return rand_int.to_bytes(length, "little")

    @classmethod
    def create_shares(
        cls,
        value: bytes,
        share_type: ShareType,
    ) -> tuple["IPAShare", "IPAShare", "IPAShare"]:
        first_share = IPAShare.generate_random_share(share_type)
        second_share = IPAShare.generate_random_share(share_type)
        third_share = IPAShare.xor(IPAShare.xor(first_share, second_share), value)

        return (
            IPAShare(left=first_share, right=second_share),
            IPAShare(left=second_share, right=third_share),
            IPAShare(left=third_share, right=first_share),
        )

    def __str__(self) -> str:
        return f"({self.left})({self.right})"

class IPAReport:
    __slots__ = [
        "mk_encap_key_ciphertext",
        "breakdown_key",
        "trigger_value",
        "timestamp",
        "info",
    ]

    def __init__(
        self,
        mk_encap_key_ciphertext: bytes,
        breakdown_key: IPAShare,
        trigger_value: IPAShare,
        timestamp: IPAShare,
        info: IPAReportInfo,
    ) -> None:
        self.mk_encap_key_ciphertext: bytes = mk_encap_key_ciphertext
        self.breakdown_key: IPAShare = breakdown_key
        self.trigger_value: IPAShare = trigger_value
        self.timestamp: IPAShare = timestamp
        self.info: IPAReportInfo = info

    def encrypt(self, public_key_string: str) -> bytes:
        share_data = (
            self.timestamp.to_bytes()
            + self.breakdown_key.to_bytes()
            + self.trigger_value.to_bytes()
        )
        encrypted = encrypt_share(
            share_data,
            self.info.event_type,
            self.info.site_domain,
            public_key_string,
            self.info.helper_domain,
        )

        print("mk_encap_key_ciphertext: ", len(self.mk_encap_key_ciphertext))
        print("enc bytes: ", len(encrypted.encrypted_to_bytes()))
        print("report info: ",len(encrypted.ipa_report_info_to_bytes()))
        return (
            self.mk_encap_key_ciphertext
            + encrypted.encrypted_to_bytes()
            + encrypted.ipa_report_info_to_bytes()
        )


def generate_report_per_helper(
    mk_share: IPAShare,
    ts_share: IPAShare,
    bk_share: IPAShare,
    tv_share: IPAShare,
    site_domain: str,
    event_type: EventType,
    pub_key: str,
    helper_domain: str,
) -> bytes:
    mk_encap_key_ciphertext = encrypt_share(
        mk_share.to_bytes(),
        event_type=event_type,
        site_domain=site_domain,
        public_key_string=pub_key,
        helper_domain=helper_domain,
    ).encrypted_to_bytes()

    return IPAReport(
        mk_encap_key_ciphertext=mk_encap_key_ciphertext,
        breakdown_key=bk_share,
        trigger_value=tv_share,
        timestamp=ts_share,
        info=IPAReportInfo(
            key_id=0,
            epoch=0,
            event_type=event_type,
            helper_domain=helper_domain,
            site_domain=site_domain,
        ),
    ).encrypt(pub_key)


def encrypt_to_file(
    file_in: str,
    dir_out: str,
    file_out_prefix: str,
    site_domain: str,
    pub_key: str,
    pub_key2: str,
    pub_key3: str,
    helper_domain: str,
    verbose=bool,
):
    encrypted_reports_1 = []
    encrypted_reports_2 = []
    encrypted_reports_3 = []

    with open(file_in, "r") as f_in:
        for line_num, line in enumerate(f_in):
            # File format: <timestamp>,<match_key>,<event_type>,<breakdown_key>,<trigger_value>
            values = line.split(",")
            assert (
                len(values) >= 5
            ), f"Corrupted file: line {line_num} has less than 5 values"
            timestamp = int(values[0].strip())
            match_key = int(values[1].strip())
            event_type = EventType(int(values[2].strip()))
            breakdown_key = int(values[3].strip())
            trigger_value = int(values[4].strip())

            mk_share = IPAShare.create_shares(
                match_key.to_bytes(8, "little"), ShareType.MATCH_KEY
            )
            ts_share = IPAShare.create_shares(
                timestamp.to_bytes(3, "little"), ShareType.TIMESTAMP
            )
            bk_share = IPAShare.create_shares(
                breakdown_key.to_bytes(1, "little"), ShareType.BREAKDOWN
            )
            tv_share = IPAShare.create_shares(
                trigger_value.to_bytes(1, "little"), ShareType.TRIGGER_VALUE
            )

            print("mk: ", mk_share[0])
            print("ts: ", ts_share[0])
            print("bk: ", bk_share[0])
            print("tv: ", tv_share[0])

            encrypted_reports_1.append(
                generate_report_per_helper(
                    mk_share=mk_share[0],
                    ts_share=ts_share[0],
                    bk_share=bk_share[0],
                    tv_share=tv_share[0],
                    site_domain=site_domain,
                    event_type=event_type,
                    pub_key=pub_key,
                    helper_domain=helper_domain,
                )
            )

            encrypted_reports_2.append(
                generate_report_per_helper(
                    mk_share=mk_share[1],
                    ts_share=ts_share[1],
                    bk_share=bk_share[1],
                    tv_share=tv_share[1],
                    site_domain=site_domain,
                    event_type=event_type,
                    pub_key=pub_key2,
                    helper_domain=helper_domain,
                )
            )

            encrypted_reports_3.append(
                generate_report_per_helper(
                    mk_share=mk_share[2],
                    ts_share=ts_share[2],
                    bk_share=bk_share[2],
                    tv_share=tv_share[2],
                    site_domain=site_domain,
                    event_type=event_type,
                    pub_key=pub_key3,
                    helper_domain=helper_domain,
                )
            )

        file_out_1 = os.path.join(dir_out, file_out_prefix + "_h1")
        with open(file_out_1, "w") as f_out:
            for i in encrypted_reports_1:
                f_out.write(i.hex() + "\n")
                if verbose:
                    print(i.hex())

        file_out_2 = os.path.join(dir_out, file_out_prefix + "_h2")
        with open(file_out_2, "w") as f_out:
            for i in encrypted_reports_2:
                f_out.write(i.hex() + "\n")
                if verbose:
                    print(i.hex())

        file_out_3 = os.path.join(dir_out, file_out_prefix + "_h3")
        with open(file_out_3, "w") as f_out:
            for i in encrypted_reports_3:
                f_out.write(i.hex() + "\n")
                if verbose:
                    print(i.hex())


def main():
    parser = argparse.ArgumentParser(
        description="Sample function for encrypting shared data for IPA query"
    )
    parser.add_argument(
        "--pub_key",
        required=True,
        help="The public key used for encryption, binary in hex encoding",
    )
    parser.add_argument(
        "--pub_key2",
        required=True,
        help="The public key for helper2 used for encryption, binary in hex encoding",
    )
    parser.add_argument(
        "--pub_key3",
        required=True,
        help="The public key for helper 3used for encryption, binary in hex encoding",
    )

    parser.add_argument(
        "--helper_domain",
        required=False,
        default="github.com/private-attribution",
        help="IPA helper domain, defaults to github.com/private-attribution",
    )
    parser.add_argument(
        "--site_domain",
        required=False,
        default="foo.example",
        help="The site domain where the event originates from",
    )
    parser.add_argument(
        "--event",
        required=False,
        type=int,
        default=0,
        help="Event type. 0 for source event, 1 for trigger event",
    )
    parser.add_argument(
        "--file_in", required=False, help="Path to file with data to be encrypted."
    )
    parser.add_argument(
        "--dir_out",
        required=False,
        help="Path to directory of output file",
    )
    parser.add_argument(
        "--file_out_prefix",
        required=False,
        default="encrypted_report_",
        help="Prefix of the output file",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="When writing to a file, also print to stdout",
    )
    parser.add_argument("data", nargs="?", help="Data to be encrypted")

    args = parser.parse_args()

    if args.data is not None:
        encrypted_data = encrypt_share(
            args.data.encode("utf-8"),
            args.event,
            args.site_domain,
            args.pub_key,
            args.helper_domain,
        )
        print(
            f"{encrypted_data.encrypted_to_bytes().hex()}"
            f"{encrypted_data.ipa_report_info_to_bytes().hex()}"
        )
    elif args.file_in is not None:
        encrypt_to_file(
            args.file_in,
            args.dir_out,
            args.file_out_prefix,
            args.site_domain,
            args.pub_key,
            args.pub_key2,
            args.pub_key3,
            args.helper_domain,
            args.verbose,
        )


if __name__ == "__main__":
    main()
