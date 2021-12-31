import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def main():
    flag = os.getenv("FLAG", "FAKE{REDACTED}").encode()
    key = os.urandom(16)
    iv = os.urandom(16)

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

    ciphertext = cipher.encrypt(pad(flag, AES.block_size))
    print(f"{iv = }")
    print(f"{ciphertext = }")

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

    while True:
        try:
            user_input = bytes.fromhex(input("> "))
            print(unpad(cipher.decrypt(user_input), AES.block_size))
        except Exception as e:
            print(e)


if __name__ == "__main__":
    main()
