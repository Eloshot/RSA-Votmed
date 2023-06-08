from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", "wb") as file:
        file.write(private_pem)
    with open("public_key.pem", "wb") as file:
        file.write(public_pem)


def encrypt_text(text, public_key_path):
    with open(public_key_path, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
    encrypted_text = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    base64_encrypted_text = base64.b64encode(encrypted_text).decode()
    print("Base64 encoded encrypted text:", base64_encrypted_text)
    return base64_encrypted_text


def decrypt_text(encrypted_text, private_key_path):
    with open(private_key_path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None,
            backend=default_backend()
        )
    decrypted_text = private_key.decrypt(
        base64.b64decode(encrypted_text),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted_text_str = decrypted_text.decode()
    print("Decrypted text:", decrypted_text_str)
    return decrypted_text_str

def main():
    while True:
        print("RSA Authentication Program")
        print("1. Generate RSA key pair")
        print("2. Encrypt text")
        print("3. Decrypt text")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            generate_key_pair()
            print("RSA key pair generated and saved.")

        elif choice == "2":
            text = input("Enter the text to encrypt: ")
            public_key_path = input("Enter the path to the public key file (or leave blank): ")
            if public_key_path.strip() == "":
                public_key_path = "public_key.pem"
            encrypted_text = encrypt_text(text, public_key_path)
            print("Encrypted text:", encrypted_text)

        elif choice == "3":
            encrypted_text = input("Enter the encrypted text: ")
            private_key_path = input("Enter the path to the private key file (or leave blank): ")
            if private_key_path.strip() == "":
                private_key_path = "private_key.pem"
            decrypted_text = decrypt_text(encrypted_text, private_key_path)
            print("Decrypted text:", decrypted_text)

        elif choice == "4":
            break

        else:
            print("Invalid choice. Please try again.")
            
if __name__ == "__main__":
    main()