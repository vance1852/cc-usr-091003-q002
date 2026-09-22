"""纯标准库 Ed25519 签名与模型摘要工具。

工厂环境只允许 Python 3.11 标准库，这里按 RFC 8032 实现 Ed25519，
测试中使用 RFC 第 7.1 节的测试向量交叉验证，不依赖 openssl 或第三方包。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Ed25519 曲线参数（RFC 8032 / RFC 7748）
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
# 基点 B 的 y 坐标 = 4/5，x 取正值
_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = ((_BY * _BY - 1) * pow(_D * _BY * _BY + 1, _P - 2, _P)) % _P
_BX = pow(_BX, (_P + 3) // 8, _P)
if (_BX * _BX - _BX * _BX * _D * _BY * _BY - 1) % _P != 0:
    _BX = (_BX * pow(2, (_P - 1) // 4, _P)) % _P
_B = (_BX, _BY)
_IDENTITY = (0, 1)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


# 基点 B 的 y 坐标 = 4/5，x 取偶符号（RFC 8032 recover_x）
_BY = (4 * pow(5, _P - 2, _P)) % _P
_u = ((_BY * _BY - 1) * pow(_D * _BY * _BY + 1, _P - 2, _P)) % _P
_BX = pow(_u, (_P + 3) // 8, _P)
if (_BX * _BX - _u) % _P != 0:
    _BX = (_BX * pow(2, (_P - 1) // 4, _P)) % _P
if (_BX * _BX - _u) % _P != 0:
    raise RuntimeError("无法恢复 Ed25519 基点 x")
if _BX & 1:
    _BX = _P - _BX
# 扩展扭曲爱德华兹坐标 (X, Y, Z, T)，x=X/Z，y=Y/Z，T=XY/Z
_IDENTITY = (0, 1, 1, 0)
_B = (_BX, _BY, 1, _BX * _BY % _P)
_2D = (2 * _D) % _P


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
    if x & 1:
        x = _P - x
    return x


def _padd(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * _2D * t2 % _P
    d = (z1 * 2 * z2) % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _pdouble(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    # dbl-2008-hwcd-2（a=-1）
    x, y, z, _ = p
    a = x * x % _P
    b = y * y % _P
    c = 2 * z * z % _P
    e = (x + y) * (x + y) - a - b
    g = b - a
    f = g - c
    h = -a - b
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mul(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _padd(result, point)
        point = _pdouble(point)
        scalar >>= 1
    return result


def _compress_ext(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _points_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return x1 * z2 % _P == x2 * z1 % _P and y1 * z2 % _P == y2 * z1 % _P


def _decompress(blob: bytes) -> tuple[int, int, int, int]:
    if len(blob) != 32:
        raise SignatureError("公钥/点长度必须为 32 字节")
    y = int.from_bytes(blob, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        raise SignatureError("点编码越界")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _P - x
    # 曲线方程校验：-x^2 + y^2 = 1 + d x^2 y^2
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _P != 0:
        raise SignatureError("点不在 Ed25519 曲线上")
    return (x, y, 1, x * y % _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _encode_scalar(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


# ---------------------------------------------------------------------------
# 对外类型
# ---------------------------------------------------------------------------


class SignatureError(ValueError):
    """签名缺失、编码错误或验签失败。"""


@dataclass(frozen=True)
class SigningKey:
    """Ed25519 私钥，保存 32 字节种子。"""

    kid: str
    seed: bytes

    def public(self) -> "PublicKey":
        scalar = _encode_scalar(_sha512(self.seed))
        return PublicKey(kid=self.kid, raw=_compress_ext(_scalar_mul(_B, scalar)))

    def sign(self, message: bytes) -> bytes:
        h = _sha512(self.seed)
        scalar = _encode_scalar(h)
        public_raw = _compress_ext(_scalar_mul(_B, scalar))
        r = int.from_bytes(_sha512(h[32:] + message), "little") % _L
        r_enc = _compress_ext(_scalar_mul(_B, r))
        k = int.from_bytes(_sha512(r_enc + public_raw + message), "little") % _L
        s = (r + k * scalar) % _L
        return r_enc + s.to_bytes(32, "little")

    @classmethod
    def generate(cls, kid: str) -> "SigningKey":
        return cls(kid=kid, seed=os.urandom(32))

    def to_dict(self) -> dict[str, Any]:
        return {"kty": "Ed25519", "kid": self.kid, "d": b64encode(self.seed)}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SigningKey":
        if raw.get("kty") != "Ed25519":
            raise SignatureError("仅支持 Ed25519 密钥")
        seed = b64decode(raw["d"])
        if len(seed) != 32:
            raise SignatureError("私钥种子必须为 32 字节")
        return cls(kid=str(raw["kid"]), seed=seed)


@dataclass(frozen=True)
class PublicKey:
    """受信任的 Ed25519 公钥（来自工厂签名公钥清单）。"""

    kid: str
    raw: bytes

    def verify(self, message: bytes, signature: bytes) -> None:
        if len(signature) != 64:
            raise SignatureError("签名长度必须为 64 字节")
        r_raw = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            raise SignatureError("签名标量 S 越界（非规范编码）")
        r_point = _decompress(r_raw)
        a_point = _decompress(self.raw)
        k = int.from_bytes(_sha512(r_raw + self.raw + message), "little") % _L
        # 余因子方程：[8]R + [8]k A == [8]S B
        left = _padd(_scalar_mul(r_point, 8), _scalar_mul(a_point, 8 * k))
        right = _scalar_mul(_B, 8 * s)
        if not _points_equal(left, right):
            raise SignatureError("签名校验失败")

    def to_dict(self) -> dict[str, Any]:
        return {"kty": "Ed25519", "kid": self.kid, "x": b64encode(self.raw)}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PublicKey":
        if raw.get("kty") != "Ed25519":
            raise SignatureError("仅支持 Ed25519 公钥")
        point = b64decode(raw["x"])
        if len(point) != 32:
            raise SignatureError("公钥必须为 32 字节")
        return cls(kid=str(raw["kid"]), raw=point)


# ---------------------------------------------------------------------------
# 摘要与规范编码
# ---------------------------------------------------------------------------


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # pragma: no cover - 仅转一层异常类型
        raise SignatureError("base64 编码非法") from exc


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(payload: Any) -> bytes:
    """生成字节唯一的规范 JSON（排序键、无空白、不转义非 ASCII）。

    字节值以 ``{"@b64": "..."}`` 标记包裹，签名双方共用同一规则。
    """

    def normalize(value: Any) -> Any:
        if isinstance(value, bytes):
            return {"@b64": b64encode(value)}
        if isinstance(value, dict):
            return {key: normalize(value[key]) for key in sorted(value)}
        if isinstance(value, (list, tuple)):
            return [normalize(item) for item in value]
        return value

    return json.dumps(
        normalize(payload),
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def sign_payload(signing_key: SigningKey, payload: dict[str, Any]) -> str:
    return b64encode(signing_key.sign(canonical_json(payload)))


def verify_payload(public_key: PublicKey, payload: dict[str, Any], signature: str) -> None:
    public_key.verify(canonical_json(payload), b64decode(signature))
