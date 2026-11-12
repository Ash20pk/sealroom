from nacl.signing import SigningKey

from sealroom.conflict import commitment
from sealroom.e2ee import ClientKey, decrypt_as_model, encrypt_to


def test_two_parties_encrypt_independently_to_model():
    model = SigningKey.generate()
    pub = bytes(model.verify_key).hex()
    a, b = encrypt_to(pub, "firm A list"), encrypt_to(pub, "firm B list")
    assert a[:64] != b[:64]  # different ephemeral keys, nothing shared
    assert decrypt_as_model(model, a) == "firm A list"
    assert decrypt_as_model(model, b) == "firm B list"


def test_response_only_readable_by_reader_key():
    reader = ClientKey.generate()
    blob = encrypt_to(reader.public_hex, "verdict")
    assert reader.decrypt(blob) == "verdict"
    try:
        ClientKey.generate().decrypt(blob)
        assert False, "another key decrypted it"
    except Exception:
        pass


def test_commitment_depends_on_salt_and_list():
    p = [{"name": "A", "role": "client", "aliases": [], "related": ""}]
    s1, s2 = "00" * 32, "11" * 32
    assert commitment(s1, p) == commitment(s1, list(p))
    assert commitment(s1, p) != commitment(s2, p)
    assert commitment(s1, p) != commitment(s1, p + p)


def test_disclosed_encryption_reproduces_ciphertext():
    from sealroom.e2ee import encrypt_disclosable
    model = SigningKey.generate()
    pub = bytes(model.verify_key).hex()
    ct, d = encrypt_disclosable(pub, "instructions")
    assert encrypt_to(pub, "instructions", **d) == ct
    assert encrypt_to(pub, "other", **d) != ct
    assert decrypt_as_model(model, ct) == "instructions"
