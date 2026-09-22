"""加密原语测试：签名/验签、JWK 与 PEM 公钥加载、篡改检测。"""

import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from arm_release.crypto import (
    RsaPublicKey,
    SignatureError,
    generate_rsa,
    sha256_bytes,
)


def _spki_der(key: RsaPublicKey) -> bytes:
    """最小 DER 编码器，仅用于在测试中生成 SubjectPublicKeyInfo。"""

    def integer(value: int) -> bytes:
        body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if body[0] & 0x80:
            body = b"\x00" + body
        return b"\x02" + _len(len(body)) + body

    def _len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    def seq(content: bytes) -> bytes:
        return b"\x30" + _len(len(content)) + content

    def bitstring(content: bytes) -> bytes:
        return b"\x03" + _len(len(content) + 1) + b"\x00" + content

    rsa_pub = seq(integer(key.n) + integer(key.e))
    alg = bytes.fromhex("300d06092a864886f70d0101010500")
    return seq(alg + bitstring(rsa_pub))


class CryptoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.priv = generate_rsa(2048)

    def test_sign_and_verify_roundtrip(self) -> None:
        msg = b"model artifact bytes"
        sig = self.priv.sign(msg)
        self.priv.public.verify(msg, sig)  # 不抛即通过

    def test_tampered_message_rejected(self) -> None:
        sig = self.priv.sign(b"original")
        with self.assertRaises(SignatureError):
            self.priv.public.verify(b"tampered", sig)

    def test_wrong_key_rejected(self) -> None:
        other = generate_rsa(2048)
        sig = self.priv.sign(b"payload")
        with self.assertRaises(SignatureError):
            other.public.verify(b"payload", sig)

    def test_bad_signature_length(self) -> None:
        with self.assertRaises(SignatureError):
            self.priv.public.verify(b"x", b"\x00" * 10)

    def test_jwk_roundtrip(self) -> None:
        jwk = self.priv.public.to_jwk()
        loaded = RsaPublicKey.from_jwk(jwk)
        loaded.verify(b"abc", self.priv.sign(b"abc"))

    def test_jwk_rejects_non_rsa(self) -> None:
        with self.assertRaises(SignatureError):
            RsaPublicKey.from_jwk({"kty": "EC"})

    def test_pem_spki_roundtrip(self) -> None:
        der = _spki_der(self.priv.public)
        pem = (
            b"-----BEGIN PUBLIC KEY-----\n"
            + base64.encodebytes(der)
            + b"-----END PUBLIC KEY-----\n"
        )
        loaded = RsaPublicKey.from_pem(pem)
        loaded.verify(b"pem", self.priv.sign(b"pem"))

    def test_pem_without_key_block(self) -> None:
        with self.assertRaises(SignatureError):
            RsaPublicKey.from_pem("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----")

    def test_digest_stable(self) -> None:
        self.assertEqual(sha256_bytes(b"abc"), sha256_bytes(b"abc"))
        self.assertTrue(sha256_bytes(b"abc").startswith("sha256:"))

    def test_short_modulus_rejected(self) -> None:
        with self.assertRaises(SignatureError):
            generate_rsa(512)


if __name__ == "__main__":
    unittest.main()
