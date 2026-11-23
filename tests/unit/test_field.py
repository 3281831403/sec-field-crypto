import base64
import hashlib
import json

import pytest

from vault.field import (
    blind_index,
    decrypt_field,
    derive_key,
    detect_tamper,
    encrypt_field,
    field_batch,
    rotate_token,
    validate_policy,
)

MASTER = b"master-material-for-tests-20261119"
PHONE = "13800000000"
AAD = "tenant-a:user-1"


def _decode_token(token: str) -> dict:
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def _encode_token(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _policy(**overrides) -> dict:
    policy = {
        "master_key": MASTER,
        "aad": "tenant:user",
        "key_scope": "tenant",
        "index_rotation": True,
    }
    policy.update(overrides)
    return policy


def _row_aad(policy: dict, row: dict) -> str:
    return policy["aad"] + ":" + row["tenant"] + ":" + row["user"]


def _mutate_ciphertext(token: str) -> str:
    payload = _decode_token(token)
    ciphertext = payload["c"]
    position = len(ciphertext) // 2
    replacement = "A" if ciphertext[position] != "A" else "B"
    payload["c"] = ciphertext[:position] + replacement + ciphertext[position + 1 :]
    return _encode_token(payload)


def test_record_move_to_other_user_rejected():
    key = derive_key(MASTER, "tenant-a")
    token = encrypt_field(key, PHONE, "tenant-a:user-1")

    with pytest.raises(ValueError):
        decrypt_field(key, token, "tenant-a:user-2")


def test_aad_is_authenticated_not_just_appended():
    key = derive_key(MASTER, "tenant-a")
    token = encrypt_field(key, PHONE, AAD)
    payload = _decode_token(token)

    assert "aad" not in payload
    assert AAD not in token
    with pytest.raises(ValueError):
        decrypt_field(key, token, "tenant-a:user-2")
    assert detect_tamper(token, "tenant-a:user-2") is True


def test_tenant_key_isolation_blocks_global_key():
    key_a = derive_key(MASTER, "tenant-a")
    key_b = derive_key(MASTER, "tenant-b")

    assert len(key_a) == 32
    assert key_a != key_b
    issues = validate_policy(_policy(key_scope="global"))
    assert any("密钥全局共享" in issue for issue in issues)


def test_blind_index_is_not_a_plain_hash():
    key = derive_key(MASTER, "tenant-a")
    index = blind_index(key, PHONE)
    plain_hash = hashlib.sha256(PHONE.encode("utf-8")).hexdigest()

    assert index == blind_index(key, PHONE)
    assert index != plain_hash
    assert len(index) == 64
    assert all(char in "0123456789abcdef" for char in index)


def test_blind_index_is_keyed_across_tenants():
    key_a = derive_key(MASTER, "tenant-a")
    key_b = derive_key(MASTER, "tenant-b")
    index_a = blind_index(key_a, PHONE)
    index_b = blind_index(key_b, PHONE)

    assert index_a != index_b
    assert blind_index(key_a, "13900000000") != index_a


def test_rotate_rejects_corrupt_old_token():
    old_key = derive_key(MASTER, "tenant-a")
    new_key = derive_key(MASTER, "tenant-b")
    token = encrypt_field(old_key, PHONE, AAD)
    corrupt = _mutate_ciphertext(token)

    with pytest.raises(ValueError):
        rotate_token(old_key, new_key, corrupt, AAD)


def test_version_downgrade_rejected():
    key = derive_key(MASTER, "tenant-a")
    payload = _decode_token(encrypt_field(key, PHONE, AAD))
    payload["v"] = 1

    with pytest.raises(ValueError, match="版本"):
        decrypt_field(key, _encode_token(payload), AAD)


def test_tamper_detection_catches_same_length_change():
    key = derive_key(MASTER, "tenant-a")
    token = encrypt_field(key, PHONE, AAD)

    assert detect_tamper(token, AAD) is False
    corrupt = _mutate_ciphertext(token)
    assert len(_decode_token(corrupt)["c"]) == len(_decode_token(token)["c"])
    assert detect_tamper(corrupt, AAD) is True
    with pytest.raises(ValueError):
        decrypt_field(key, corrupt, AAD)


def test_policy_flags_empty_aad():
    issues = validate_policy(_policy(aad=""))

    assert len(issues) == 1
    assert "附加数据为空" in issues[0]


def test_batch_rows_do_not_share_key_or_index():
    rows = [
        {"tenant": "tenant-a", "user": "user-1", "phone": PHONE},
        {"tenant": "tenant-b", "user": "user-2", "phone": PHONE},
    ]
    policy = _policy()
    result = field_batch(rows, policy)

    assert result["problems"] == {}
    assert result["tokens"][0] != result["tokens"][1]
    assert result["indexes"][0] != result["indexes"][1]

    for index, row in enumerate(rows):
        key = derive_key(policy["master_key"], row["tenant"])
        assert decrypt_field(key, result["tokens"][index], _row_aad(policy, row)) == row["phone"]
