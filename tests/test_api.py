def test_highlevel():
    age = Age()

    # uses ~/.config/age/keys.txt and ~/.ssh/id_*    
    age.load_default_keys()

    data = age.decrypt()
    encrypted = age.encrypt(data, [
        "alias:jojonas",
        "github:FiloSotille",
        "pubkey:98W5ph53zfPGOzEOH-fMojQ4jUY7VLEmtmozREqnw4I",
    ])

    print(encrypted)


def test_keyring():
    password_key = age.PasswordKey("mysecretpassword123#")
    age_key = age.AgeKey("AGE_SECRET_KEY_RQvvHYA29yZk8Lelpiz8lW7QdlxkE4djb1NOjLgeUFg")
    ssh_rsa_key = age.SSHRSAKey(b"PRIVATE KEY GOES HERE")
    ssh_ed25519_key = age.SSHED25519Key(b"PRIVATE KEY GOES HERE")

    key = password_key
    master_key = key.recipient_decrypt(b"bBjlhJVYZeE4aqUdmtRHfw", "32768", b"ZV_AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k")
    