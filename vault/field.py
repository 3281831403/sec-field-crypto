"""手机号字段的认证加密、盲索引与批量策略契约。

令牌是 ASCII 字符串：先把紧凑 JSON 编码成 UTF-8，再做带填充的
base64.urlsafe_b64encode。JSON 固定包含四个键：

    {"v": 2, "c": "...", "t": "...", "h": "..."}

v 是整数版本号，当前唯一合法值是 2；c 是密文字节的 urlsafe base64；t 是
HMAC-SHA256 认证标签的 urlsafe base64；h 是 SHA-256 结构校验值的 urlsafe
base64，覆盖 v、AAD、c 与 t，供 detect_tamper 在没有密钥时发现改动。令牌
不保存明文 AAD，也不保存明文手机号。AAD 必须真正参与认证，不能只是拼接在
令牌尾部。所有比较容差为 0：版本必须精确等于 2，AAD 必须逐字节相等，空
AAD 一律拒绝。

实现只使用标准库 hashlib、hmac、base64、json；加密必须确定性，禁止随机数，
密钥材料全部显式传入。
"""

import base64
import hashlib
import hmac
import json

VERSION = 2
_TOKEN_KEYS = frozenset(("v", "c", "t", "h"))

_DOMAIN_TENANT_KEY = b"vault-field-tenant-key-v1"
_DOMAIN_ENCRYPTION = b"vault-field-encryption-v1"
_DOMAIN_AUTHENTICATION = b"vault-field-authentication-v1"
_DOMAIN_INDEX = b"vault-field-blind-index-v1"
_DOMAIN_TAG = b"vault-field-tag-v1"
_DOMAIN_STRUCTURE = b"vault-field-structure-hash-v1"


def _require_bytes(value, name):
    if not isinstance(value, bytes) or not value:
        raise ValueError(f"{name} 必须是非空 bytes")


def _require_nonempty_str(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} 必须是非空字符串")


def _frame(*parts: bytes) -> bytes:
    """用 ``长度:内容`` 分帧拼接字节，杜绝分隔符歧义。"""
    framed = []
    for part in parts:
        framed.append(str(len(part)).encode("ascii"))
        framed.append(b":")
        framed.append(part)
    return b"".join(framed)


def _keystream(seed: bytes, length: int) -> bytes:
    """HMAC-SHA256 计数器模式生成确定性密钥流，不使用任何随机数。"""
    blocks = []
    produced = 0
    counter = 1
    while produced < length:
        block = hmac.new(
            seed,
            b"counter:" + str(counter).encode("ascii"),
            hashlib.sha256,
        ).digest()
        blocks.append(block)
        produced += len(block)
        counter += 1
    return b"".join(blocks)[:length]


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(data, stream))


def derive_key(master: bytes, tenant: str) -> bytes:
    """按租户派生数据密钥。

    契约：
    - master 必须是非空 bytes，tenant 必须是非空 str，否则抛 ValueError。
    - 租户按 UTF-8 精确匹配，大小写不同即视为不同租户，容差为 0。
    - 使用 HMAC-SHA256 做域分离，返回 32 字节；相同输入必须得到相同结果。
    - 不同租户必须得到不同密钥，禁止把 master 直接当作所有租户共享的密钥。
    """
    _require_bytes(master, "master")
    _require_nonempty_str(tenant, "tenant")
    return hmac.new(
        master,
        _DOMAIN_TENANT_KEY + tenant.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _split_keys(key: bytes) -> tuple[bytes, bytes]:
    """从字段密钥派生出相互独立的加密密钥与认证密钥。"""
    encryption_key = hmac.new(key, _DOMAIN_ENCRYPTION, hashlib.sha256).digest()
    authentication_key = hmac.new(key, _DOMAIN_AUTHENTICATION, hashlib.sha256).digest()
    return encryption_key, authentication_key


def _structure_hash(aad_bytes: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """无密钥结构校验值，覆盖版本、AAD、密文与标签。"""
    return hashlib.sha256(
        _frame(
            _DOMAIN_STRUCTURE,
            str(VERSION).encode("ascii"),
            aad_bytes,
            ciphertext,
            tag,
        )
    ).digest()


def encrypt_field(key: bytes, plaintext: str, aad: str) -> str:
    """加密字段并返回版本化令牌。

    契约：
    - key 必须是非空 bytes，plaintext 必须是 str，aad 必须是非空 str；
      空 AAD 直接抛 ValueError。
    - 令牌版本 v 精确写为整数 2。
    - t 是基于 key 的 HMAC-SHA256 标签，认证范围必须包含 AAD 与密文；禁止
      只把 AAD 明文附在令牌尾部而不参与认证。
    - h 是 SHA-256 结构校验值，覆盖 v、AAD、c 与 t。
    - 令牌中不得出现明文 AAD 字段或明文手机号。
    - 加密确定性：同一 key、plaintext、aad 必须得到完全相同的令牌，不使用
      随机数或当前时间。
    """
    _require_bytes(key, "key")
    if not isinstance(plaintext, str):
        raise ValueError("plaintext 必须是字符串")
    _require_nonempty_str(aad, "aad")

    aad_bytes = aad.encode("utf-8")
    plaintext_bytes = plaintext.encode("utf-8")
    encryption_key, authentication_key = _split_keys(key)

    ciphertext = _xor(
        plaintext_bytes,
        _keystream(encryption_key, len(plaintext_bytes)),
    )
    # AAD 以分帧方式进入 HMAC，真正参与认证；令牌中不保存明文 AAD。
    tag = hmac.new(
        authentication_key,
        _frame(_DOMAIN_TAG, aad_bytes, ciphertext),
        hashlib.sha256,
    ).digest()
    structure_hash = _structure_hash(aad_bytes, ciphertext, tag)

    payload = {
        "v": VERSION,
        "c": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        "t": base64.urlsafe_b64encode(tag).decode("ascii"),
        "h": base64.urlsafe_b64encode(structure_hash).decode("ascii"),
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _parse_token(token: str):
    """解析令牌并返回 (版本, 密文, 标签, 结构校验值)，畸形一律抛 ValueError。"""
    if not isinstance(token, str):
        raise ValueError("令牌必须是字符串")
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("令牌无法解析或 base64 非法") from exc

    if not isinstance(payload, dict) or frozenset(payload.keys()) != _TOKEN_KEYS:
        raise ValueError("令牌字段缺失或包含非法字段")
    if not all(isinstance(payload[name], str) for name in ("c", "t", "h")):
        raise ValueError("令牌字段类型非法")

    try:
        ciphertext = base64.urlsafe_b64decode(payload["c"].encode("ascii"))
        tag = base64.urlsafe_b64decode(payload["t"].encode("ascii"))
        structure_hash = base64.urlsafe_b64decode(payload["h"].encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("令牌中的 base64 数据非法") from exc

    return payload["v"], ciphertext, tag, structure_hash


def decrypt_field(key: bytes, token: str, aad: str) -> str:
    """校验令牌并解密，返回原始明文字符串。

    契约：
    - 令牌无法解析、字段缺失、base64 非法或明文不是 UTF-8 时抛 ValueError。
    - 校验顺序固定为：先校验版本 v 精确等于 2，失败消息必须包含 版本；再
      校验 aad 非空且与加密时 AAD 精确相等；再校验 h；最后校验 HMAC 标签 t。
    - 版本 1 或其他旧版本不得回退兼容，AAD 不得忽略，所有比较容差为 0。
    - 任一校验失败抛 ValueError，绝不返回未经认证的明文。
    """
    _require_bytes(key, "key")
    version, ciphertext, tag, structure_hash = _parse_token(token)

    # 1. 版本必须精确等于 2，bool 不冒充整数，旧版本不做回退兼容。
    if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
        raise ValueError(f"不支持的令牌版本，当前仅支持版本 {VERSION}")

    # 2. AAD 必须非空；是否与加密时一致由后续 h、t 逐字节校验。
    _require_nonempty_str(aad, "aad")
    aad_bytes = aad.encode("utf-8")

    # 3. 无密钥结构校验：覆盖 v、AAD、c、t，同长度单字节改动也会失配。
    expected_structure = _structure_hash(aad_bytes, ciphertext, tag)
    if not hmac.compare_digest(expected_structure, structure_hash):
        raise ValueError("结构校验值不匹配，令牌可能已被篡改或附加数据不一致")

    # 4. 带密钥的 HMAC 认证标签，AAD 与密文均在认证范围内。
    _, authentication_key = _split_keys(key)
    expected_tag = hmac.new(
        authentication_key,
        _frame(_DOMAIN_TAG, aad_bytes, ciphertext),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("认证标签校验失败")

    # 5. 全部校验通过后才解密；UTF-8 失败同样拒绝，绝不返回未经认证的明文。
    encryption_key, _ = _split_keys(key)
    plaintext_bytes = _xor(ciphertext, _keystream(encryption_key, len(ciphertext)))
    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("解密结果不是合法 UTF-8 明文") from exc


def blind_index(key: bytes, value: str) -> str:
    """生成可检索、确定性且不可逆的盲索引。

    契约：
    - key 必须是非空 bytes，value 必须是非空 str，否则抛 ValueError。
    - 使用带域分离的 HMAC-SHA256，返回 64 位小写十六进制字符串。
    - 相同 key 与 value 必须得到相同索引；不同 key 即使 value 相同也必须
      得到不同索引。
    - 结果不得等于 sha256(value) 的十六进制值，禁止对明文做无密钥哈希。
    """
    _require_bytes(key, "key")
    _require_nonempty_str(value, "value")
    return hmac.new(
        key,
        _DOMAIN_INDEX + value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def rotate_token(old_key: bytes, new_key: bytes, token: str, aad: str) -> str:
    """把令牌重新加密到新密钥，返回新令牌。

    契约：
    - old_key、new_key 必须是非空 bytes，aad 必须是非空 str。
    - 必须先用 old_key 完整执行 decrypt_field，校验版本、AAD、h 与标签 t；
      旧令牌损坏或 AAD 不符时直接抛 ValueError，绝不把解出的错误值重新加密。
    - 校验通过后用 new_key 与同一 aad 调用 encrypt_field，版本保持 2。
    """
    _require_bytes(old_key, "old_key")
    _require_bytes(new_key, "new_key")
    _require_nonempty_str(aad, "aad")
    # 完整走一遍解密校验，任何一环失败都直接抛出，不会产生重加密结果。
    plaintext = decrypt_field(old_key, token, aad)
    return encrypt_field(new_key, plaintext, aad)


def detect_tamper(token: str, aad: str) -> bool:
    """无需密钥地检测令牌是否被改动。

    契约：
    - 始终返回 bool，不抛异常。畸形输入、字段缺失、base64 非法、版本不是
      2、AAD 为空或与令牌校验值不符、h 不匹配时返回 True。
    - 仅当令牌完整可解析且 h 在给定 AAD 下匹配时返回 False。
    - 必须实际比较内容，不能只比较总长度；同长度单字节改动必须返回 True。
    - 本函数只做无密钥结构检测，强完整性仍由 decrypt_field 的标签 t 保证。
    """
    try:
        version, ciphertext, tag, structure_hash = _parse_token(token)
        if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
            return True
        if not isinstance(aad, str) or not aad:
            return True
        expected = _structure_hash(aad.encode("utf-8"), ciphertext, tag)
        return not hmac.compare_digest(expected, structure_hash)
    except Exception:
        return True


def validate_policy(policy) -> list[str]:
    """检查字段加密策略，返回问题列表，空列表表示通过。

    policy 是 dict，至少包含 aad、key_scope、index_rotation。检查顺序固定：
    1. aad 缺失、不是字符串或去除首尾空白后为空；问题文本必须包含
       附加数据为空。
    2. key_scope 不是 tenant；问题文本必须包含 密钥全局共享。
    3. index_rotation 不是 True；问题文本必须包含 未启用索引轮换。

    每个问题一个字符串，顺序与上述检查顺序一致；不要因为一个问题而跳过
    后续检查。
    """
    settings = policy if isinstance(policy, dict) else {}
    issues = []

    aad = settings.get("aad")
    if not isinstance(aad, str) or not aad.strip():
        issues.append("附加数据为空：策略必须提供非空 AAD 以绑定记录归属")

    if settings.get("key_scope") != "tenant":
        issues.append("密钥全局共享：密钥作用域必须为 tenant，按租户隔离派生")

    if settings.get("index_rotation") is not True:
        issues.append("未启用索引轮换：index_rotation 必须显式为 True")

    return issues


def field_batch(rows, policy) -> dict:
    """批量加密手机号并生成盲索引，各行完全独立。

    rows 是 list[dict]，每行包含非空字符串 tenant、user、phone。policy 至少
    包含 master_key、aad、key_scope、index_rotation。

    处理规则：
    - 先调用 validate_policy，返回非空问题列表时抛 ValueError。
    - 每行独立派生密钥与索引键，禁止复用上一行的密钥、AAD 或索引状态：
      key = derive_key(policy["master_key"], row["tenant"])
      aad = policy["aad"] + ":" + row["tenant"] + ":" + row["user"]
      token = encrypt_field(key, row["phone"], aad)
      index_key = derive_key(key, "blind-index-v1")
      index = blind_index(index_key, row["phone"])
    - 单行失败只影响该行，后续行继续处理；不得原地修改 rows 或 policy。
    - 返回 {"tokens": list, "indexes": list, "problems": dict}。tokens 与
      indexes 和 rows 等长，失败位置为 None；problems 以失败行下标为键，
      值为错误文本。成功行不写入 problems。
    """
    issues = validate_policy(policy)
    if issues:
        raise ValueError("策略校验失败：" + "；".join(issues))

    tokens = []
    indexes = []
    problems = {}

    for position, row in enumerate(rows):
        try:
            # 每行独立派生，密钥、AAD、索引键均不从上行继承或复用。
            key = derive_key(policy["master_key"], row["tenant"])
            row_aad = policy["aad"] + ":" + row["tenant"] + ":" + row["user"]
            token = encrypt_field(key, row["phone"], row_aad)
            index_key = derive_key(key, "blind-index-v1")
            index = blind_index(index_key, row["phone"])
        except Exception as exc:
            tokens.append(None)
            indexes.append(None)
            problems[position] = str(exc)
        else:
            tokens.append(token)
            indexes.append(index)

    return {"tokens": tokens, "indexes": indexes, "problems": problems}
