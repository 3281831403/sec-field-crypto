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


def derive_key(master: bytes, tenant: str) -> bytes:
    """按租户派生数据密钥。

    契约：
    - master 必须是非空 bytes，tenant 必须是非空 str，否则抛 ValueError。
    - 租户按 UTF-8 精确匹配，大小写不同即视为不同租户，容差为 0。
    - 使用 HMAC-SHA256 做域分离，返回 32 字节；相同输入必须得到相同结果。
    - 不同租户必须得到不同密钥，禁止把 master 直接当作所有租户共享的密钥。
    """
    raise NotImplementedError


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
    raise NotImplementedError


def decrypt_field(key: bytes, token: str, aad: str) -> str:
    """校验令牌并解密，返回原始明文字符串。

    契约：
    - 令牌无法解析、字段缺失、base64 非法或明文不是 UTF-8 时抛 ValueError。
    - 校验顺序固定为：先校验版本 v 精确等于 2，失败消息必须包含 版本；再
      校验 aad 非空且与加密时 AAD 精确相等；再校验 h；最后校验 HMAC 标签 t。
    - 版本 1 或其他旧版本不得回退兼容，AAD 不得忽略，所有比较容差为 0。
    - 任一校验失败抛 ValueError，绝不返回未经认证的明文。
    """
    raise NotImplementedError


def blind_index(key: bytes, value: str) -> str:
    """生成可检索、确定性且不可逆的盲索引。

    契约：
    - key 必须是非空 bytes，value 必须是非空 str，否则抛 ValueError。
    - 使用带域分离的 HMAC-SHA256，返回 64 位小写十六进制字符串。
    - 相同 key 与 value 必须得到相同索引；不同 key 即使 value 相同也必须
      得到不同索引。
    - 结果不得等于 sha256(value) 的十六进制值，禁止对明文做无密钥哈希。
    """
    raise NotImplementedError


def rotate_token(old_key: bytes, new_key: bytes, token: str, aad: str) -> str:
    """把令牌重新加密到新密钥，返回新令牌。

    契约：
    - old_key、new_key 必须是非空 bytes，aad 必须是非空 str。
    - 必须先用 old_key 完整执行 decrypt_field，校验版本、AAD、h 与标签 t；
      旧令牌损坏或 AAD 不符时直接抛 ValueError，绝不把解出的错误值重新加密。
    - 校验通过后用 new_key 与同一 aad 调用 encrypt_field，版本保持 2。
    """
    raise NotImplementedError


def detect_tamper(token: str, aad: str) -> bool:
    """无需密钥地检测令牌是否被改动。

    契约：
    - 始终返回 bool，不抛异常。畸形输入、字段缺失、base64 非法、版本不是
      2、AAD 为空或与令牌校验值不符、h 不匹配时返回 True。
    - 仅当令牌完整可解析且 h 在给定 AAD 下匹配时返回 False。
    - 必须实际比较内容，不能只比较总长度；同长度单字节改动必须返回 True。
    - 本函数只做无密钥结构检测，强完整性仍由 decrypt_field 的标签 t 保证。
    """
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError
