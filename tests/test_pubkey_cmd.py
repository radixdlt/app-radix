def test_get_public_key(cmd):
    pub_key, chain_code = cmd.get_public_key(
        bip32_path="m/44'/1022'/2'/1/3", display=False
    )  # type: bytes, bytes

    assert pub_key.hex() == "apa"
    assert len(pub_key) == 65
    assert len(chain_code) == 32

    pub_key2, chain_code2 = cmd.get_public_key(
        bip32_path="m/44'/1022'/0'/0/0", display=False
    )  # type: bytes, bytes

    assert len(pub_key2) == 65
    assert len(chain_code2) == 32
