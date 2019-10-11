import io

from age.file import Encryptor, Decryptor
from age.keys.password import PasswordKey


def test_filippos_scrypt_file():
    stream = io.BytesIO(
        b"This is a file encrypted with age-tool.com, version 1\n"
        + b"-> scrypt tEECB8zbOo-qDg4_5pRtZA 32768\n"
        + b"meRGw2VuLYCokpCcH45vHIOV2YBySPM0q7eOK9iZvWM\n"
        + b"--- ChaChaPoly bxrGJtla-PK5Fkk4OPxUOfK3GNSOv73o79Ypn2VvtUY\n"
        + b"xxx"
    )
    key = PasswordKey(b"twitch.tv/filosottile")
    with Decryptor([key], stream) as decryptor:
        assert decryptor
