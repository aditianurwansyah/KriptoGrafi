from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import time

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def encrypt_rsa(text, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(text.encode())

def decrypt_rsa(ciphertext_bytes, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext_bytes).decode()

def main():
    print("="*60)
    print("RSA - ENKRIPSI/DEKRIPSI") 
    print("="*60)

    text = input("\nMasukkan teks rahasia (≤200 karakter): ")
    if len(text) > 200:
        text = text[:200]
        print("⚠️ Dipotong menjadi 200 karakter.")

    priv, pub = generate_rsa_keys()

    # Enkripsi → bytes → base64
    start_time = time.time()
    ct_bytes = encrypt_rsa(text, pub)
    ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
    enc_time = time.time() - start_time

    print(f"\n🔓 Plaintext        : {text}") 
    print(f"🔒 Ciphertext         : {ct_b64}")
    print(f"⏱️  Waktu enkripsi    : {enc_time:.6f} detik")

    # Dekripsi
    start_time = time.time()
    ct_bytes_restored = base64.b64decode(ct_b64)
    decrypted = decrypt_rsa(ct_bytes_restored, priv)
    dec_time = time.time() - start_time

    print(f"\n🔓 Hasil dekripsi     : {decrypted}")
    print(f"⏱️  Waktu dekripsi    : {dec_time:.6f} detik")

if __name__ == "__main__":
    main() 