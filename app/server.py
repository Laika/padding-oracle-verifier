import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def main():
    flag = os.getenvb(b"FLAG", b"FAKE{REDACTED}")
    key = os.urandom(16)
    iv = os.urandom(16)

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

    ciphertext = cipher.encrypt(pad(flag, AES.block_size)).hex()
    print(ciphertext)
    print(iv.hex())

    while True:
        cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
        try:
            user_input = bytes.fromhex(input("> ").strip())
            unpad(cipher.decrypt(user_input), AES.block_size)
            print("ok")
        except Exception as e:
            print(f"error: {e}")


if __name__ == "__main__":
    main()
