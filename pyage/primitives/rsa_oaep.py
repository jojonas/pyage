from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_ssh_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend


def _padding(label):
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=label,
    )


def rsa_encrypt(ssh_key, label, plaintext):
    public_key = load_ssh_public_key(
        data=ssh_key,
        backend=default_backend()
    )

    return public_key.encrypt(
        plaintext=plaintext,
        padding=_padding(label)
    )


def rsa_decrypt(pem_data, label, ciphertext):
    # TODO: Add support for password-protected private keys

    private_key = load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )

    return private_key.decrypt(
        ciphertext=ciphertext,
        padding=_padding(label)
    )
