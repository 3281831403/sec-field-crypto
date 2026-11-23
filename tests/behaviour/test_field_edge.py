import pytest

from vault.field import (
    blind_index,
    decrypt_field,
    derive_key,
    detect_tamper,
    encrypt_field,
    field_batch,
    rotate_token,
)

MASTER = b"master-material-for-tests-20261119"
PHONE = "13800000000"
AAD = "tenant-a:user-1"


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


def test_encrypt_then_decrypt_roundtrip():
    key = derive_key(MASTER, "tenant-a")
    token = encrypt_field(key, PHONE, AAD)

    assert isinstance(token, str)
    assert token != PHONE
    assert PHONE not in token
    assert decrypt_field(key, token, AAD) == PHONE


def test_aad_mismatch_rejected():
    key = derive_key(MASTER, "tenant-a")
    token = encrypt_field(key, PHONE, AAD)

    with pytest.raises(ValueError):
        decrypt_field(key, token, "tenant-a:user-2")
    assert detect_tamper(token, "tenant-a:user-2") is True


def test_cross_tenant_decrypt_fails():
    key_a = derive_key(MASTER, "tenant-a")
    key_b = derive_key(MASTER, "tenant-b")
    token_a = encrypt_field(key_a, PHONE, AAD)
    token_b = encrypt_field(key_b, PHONE, AAD)

    assert token_a != token_b
    with pytest.raises(ValueError):
        decrypt_field(key_b, token_a, AAD)


def test_rotate_then_decrypt():
    old_key = derive_key(MASTER, "tenant-a")
    new_key = derive_key(MASTER, "tenant-b")
    token = encrypt_field(old_key, PHONE, AAD)

    rotated = rotate_token(old_key, new_key, token, AAD)

    assert rotated != token
    assert decrypt_field(new_key, rotated, AAD) == PHONE
    with pytest.raises(ValueError):
        decrypt_field(old_key, rotated, AAD)


def test_two_batches_match_single_processing():
    rows = [
        {"tenant": "tenant-a", "user": "user-1", "phone": PHONE},
        {"tenant": "tenant-b", "user": "user-2", "phone": "13900000000"},
        {"tenant": "tenant-a", "user": "user-3", "phone": PHONE},
    ]
    policy = _policy()
    first = field_batch(rows, policy)
    second = field_batch(rows, policy)

    assert first["tokens"] == second["tokens"]
    assert first["indexes"] == second["indexes"]
    assert first["problems"] == {}
    assert second["problems"] == {}

    expected_tokens = []
    expected_indexes = []
    for row in rows:
        key = derive_key(policy["master_key"], row["tenant"])
        expected_tokens.append(encrypt_field(key, row["phone"], _row_aad(policy, row)))
        index_key = derive_key(key, "blind-index-v1")
        expected_indexes.append(blind_index(index_key, row["phone"]))

    assert first["tokens"] == expected_tokens
    assert first["indexes"] == expected_indexes
