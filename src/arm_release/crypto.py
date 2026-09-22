"""签名与摘要原语。

工厂的签名公钥可能是 PEM（SPKI 或 PKCS#1），也可能是部署系统导出的
JWK 风格 JSON。运行环境不能依赖第三方加密库，因此这里用标准库实现
RSA + RSASSA-PKCS1-v1_5 + SHA-256，私钥签发仅供测试与样例重建使用。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

# RFC 8017 9.2：SHA-256 的 DigestInfo DER 前缀。
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class SignatureError(ValueError):
    """签名缺失、格式错误或验签失败。"""


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _b64u_encode(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _b64u_decode(value: str) -> int:
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + padding), "big")


@dataclass(frozen=True)
class RsaPublicKey:
    n: int
    e: int

    def to_jwk(self) -> dict[str, str]:
        return {"kty": "RSA", "n": _b64u_encode(self.n), "e": _b64u_encode(self.e)}

    @classmethod
    def from_jwk(cls, raw: dict[str, Any]) -> "RsaPublicKey":
        if raw.get("kty") != "RSA":
            raise SignatureError("仅支持 RSA 公钥")
        try:
            return cls(n=_b64u_decode(raw["n"]), e=_b64u_decode(raw["e"]))
        except (KeyError, ValueError, binascii.Error) as exc:
            raise SignatureError("RSA 公钥字段无效") from exc

    @classmethod
    def from_pem(cls, pem: str | bytes) -> "RsaPublicKey":
        if isinstance(pem, str):
            pem = pem.encode()
        keys: list[RsaPublicKey] = []
        current: list[bytes] | None = None
        kind = ""
        for line in pem.splitlines():
            line = line.strip()
            if line.startswith(b"-----BEGIN "):
                kind = line.decode().removeprefix("-----BEGIN ").removesuffix("-----")
                current = []
            elif line.startswith(b"-----END"):
                if current is None:
                    raise SignatureError("PEM 结束标记缺少开始标记")
                try:
                    der = base64.b64decode(b"".join(current))
                except binascii.Error as exc:
                    raise SignatureError("PEM 块不是合法 base64") from exc
                keys.append(_rsa_public_from_der(der, kind))
                current = None
                kind = ""
            elif current is not None and line:
                current.append(line)
        if current is not None:
            raise SignatureError("PEM 块未闭合")
        if not keys:
            raise SignatureError("未在 PEM 中找到公钥块")
        return keys[0]

    def verify(self, message: bytes, signature: bytes) -> None:
        """严格校验，失败即抛 SignatureError。"""

        size = max(1, (self.n.bit_length() + 7) // 8)
        if len(signature) != size:
            raise SignatureError("签名长度与模数不匹配")
        digest = hashlib.sha256(message).digest()
        t_value = _SHA256_DIGEST_INFO + digest
        pad_len = size - len(t_value) - 3
        if pad_len < 8:
            raise SignatureError("模数过短，无法容纳 PKCS#1 v1.5 编码")
        expected = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + t_value
        try:
            decoded = pow(int.from_bytes(signature, "big"), self.e, self.n)
            actual = decoded.to_bytes(size, "big")
        except OverflowError as exc:
            raise SignatureError("签名数值越界") from exc
        if not hmac.compare_digest(actual, expected):
            raise SignatureError("模型签名校验失败")


@dataclass(frozen=True)
class RsaPrivateKey:
    n: int
    e: int
    d: int

    @property
    def public(self) -> RsaPublicKey:
        return RsaPublicKey(n=self.n, e=self.e)

    def to_jwk(self) -> dict[str, str]:
        return {
            "kty": "RSA",
            "n": _b64u_encode(self.n),
            "e": _b64u_encode(self.e),
            "d": _b64u_encode(self.d),
        }

    @classmethod
    def from_jwk(cls, raw: dict[str, Any]) -> "RsaPrivateKey":
        pub = RsaPublicKey.from_jwk(raw)
        try:
            return cls(n=pub.n, e=pub.e, d=_b64u_decode(raw["d"]))
        except (KeyError, ValueError) as exc:
            raise SignatureError("RSA 私钥字段无效") from exc

    def sign(self, message: bytes) -> bytes:
        size = max(1, (self.n.bit_length() + 7) // 8)
        t_value = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
        pad_len = size - len(t_value) - 3
        if pad_len < 8:
            raise SignatureError("模数过短，无法完成签名")
        encoded = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + t_value
        return pow(int.from_bytes(encoded, "big"), self.d, self.n).to_bytes(size, "big")


# --- 最小 DER 读取，仅用于 RSA 公钥 -------------------------------------


def _tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[start : start + count], "big")
        start += count
    return tag, start, start + length


def _two_integers(data: bytes) -> tuple[int, int]:
    _, start, end = _tlv(data, 0)  # 外层 SEQUENCE
    _, n_start, n_end = _tlv(data, start)
    _, e_start, e_end = _tlv(data, n_end)
    if e_end != end:
        raise SignatureError("RSA 公钥结构含多余字节")
    return int.from_bytes(data[n_start:n_end], "big"), int.from_bytes(
        data[e_start:e_end], "big"
    )


def _rsa_public_from_der(der: bytes, kind: str) -> RsaPublicKey:
    try:
        if kind in ("RSA PUBLIC KEY",):
            n, e = _two_integers(der)
        elif kind in ("PUBLIC KEY",):
            _, start, end = _tlv(der, 0)
            _, _, alg_end = _tlv(der, start)  # AlgorithmIdentifier
            tag, bits_start, bits_end = _tlv(der, alg_end)
            if tag != 0x03 or bits_end != end or der[bits_start] != 0:
                raise SignatureError("SubjectPublicKeyInfo 结构异常")
            n, e = _two_integers(der[bits_start + 1 : bits_end])
        else:
            raise SignatureError(f"不支持的 PEM 块类型：{kind}")
    except IndexError as exc:
        raise SignatureError("公钥 DER 被截断") from exc
    return RsaPublicKey(n=n, e=e)


# --- 纯 Python RSA 密钥生成（测试/样例） --------------------------------

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
]


def _is_prime(candidate: int, rounds: int = 8) -> bool:
    for prime in _SMALL_PRIMES:
        if candidate % prime == 0:
            return candidate == prime
    d_value = candidate - 1
    s_value = 0
    while d_value % 2 == 0:
        s_value += 1
        d_value //= 2
    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        x_value = pow(base, d_value, candidate)
        if x_value in (1, candidate - 1):
            continue
        for _ in range(s_value - 1):
            x_value = pow(x_value, 2, candidate)
            if x_value == candidate - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    low = 1 << (bits - 1)
    high = 1 << bits
    while True:
        candidate = secrets.randbelow(high - low) | low | 1
        if _is_prime(candidate):
            return candidate


def generate_rsa(bits: int = 2048) -> RsaPrivateKey:
    if bits < 1024:
        raise SignatureError("RSA 模数不得短于 1024 位")
    e_value = 65537
    while True:
        p_value = _prime(bits // 2)
        q_value = _prime(bits - bits // 2)
        if p_value == q_value:
            continue
        phi = (p_value - 1) * (q_value - 1)
        if phi % e_value == 0:
            continue
        n_value = p_value * q_value
        d_value = pow(e_value, -1, phi)
        return RsaPrivateKey(n=n_value, e=e_value, d=d_value)
