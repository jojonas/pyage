from age.recipients.helpers import get_recipient
from age.recipients.x25519 import X25519Recipient


def test_parse_recipient_line():
    recipient = get_recipient(
        "X25519",
        ["CJM36AHmTbdHSuOQL-NESqyVQE75f2e610iRdLPEN20"],
        "C3ZAeY64NXS4QFrksLm3EGz-uPRyI0eQsWw7LWbbYig",
    )
    assert isinstance(recipient, X25519Recipient)
    assert recipient.derived_secret == bytes.fromhex(
        "089337e801e64db7474ae3902fe3444aac95404ef97f67bad7489174b3c4376d"
    )
    assert recipient.encrypted_file_key == bytes.fromhex(
        "0b7640798eb83574b8405ae4b0b9b7106cfeb8f472234790b16c3b2d66db6228"
    )
