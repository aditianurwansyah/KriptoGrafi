from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time

def generate_rsa_keys():
    """Generate RSA public and private keys"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_aes(text, key):
    """Encrypt text using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode(), AES.block_size))
    return cipher.iv + ciphertext  # IV + ciphertext

def decrypt_aes(ciphertext, key):
    """Decrypt text using AES-256-CBC"""
    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
    return plaintext.decode()

def encrypt_rsa(text, public_key):
    """Encrypt text using RSA-OAEP"""
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    # RSA can only encrypt small data, so we'll use a short test string
    # For longer texts, you'd typically encrypt an AES key with RSA
    ciphertext = cipher.encrypt(text.encode())
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    """Decrypt text using RSA-OAEP"""
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

def main():
    print("="*50)
    print("IMPLEMENTASI ENKRIPSI DAN DEKRIPSI MENGGUNAKAN AES DAN RSA")
    print("="*50)

    # Input teks rahasia dari pengguna
    plaintext = input("\nMasukkan teks rahasia: ")

    # --- AES Encryption ---
    print("\n" + "-"*30)
    print("ENKRIPSI DAN DEKRIPSI DENGAN AES")
    print("-"*30)

    aes_key = get_random_bytes(32)  # 256-bit key for AES

    start_time = time.time()
    aes_ciphertext = encrypt_aes(plaintext, aes_key)
    aes_encrypt_time = time.time() - start_time

    print(f"\nHasil Enkripsi AES (dalam bytes): {aes_ciphertext}")
    print(f"Waktu enkripsi AES: {aes_encrypt_time:.6f} detik")

    start_time = time.time()
    aes_decrypted = decrypt_aes(aes_ciphertext, aes_key)
    aes_decrypt_time = time.time() - start_time

    print(f"\nHasil Dekripsi AES: {aes_decrypted}")
    print(f"Waktu dekripsi AES: {aes_decrypt_time:.6f} detik")

    # --- RSA Encryption ---
    print("\n" + "-"*30)
    print("ENKRIPSI DAN DEKRIPSI DENGAN RSA")
    print("-"*30)

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # RSA hanya bisa mengenkripsi data kecil (sekitar 245 byte untuk 2048-bit key)
    # Jadi kita batasi teksnya agar tidak terlalu panjang
    rsa_plaintext = plaintext[:200] if len(plaintext) > 200 else plaintext
    print(f"\nTeks RSA (dibatasi 200 karakter): {rsa_plaintext}")

    start_time = time.time()
    rsa_ciphertext = encrypt_rsa(rsa_plaintext, public_key)
    rsa_encrypt_time = time.time() - start_time

    print(f"\nHasil Enkripsi RSA (dalam bytes): {rsa_ciphertext}")
    print(f"Waktu enkripsi RSA: {rsa_encrypt_time:.6f} detik")

    start_time = time.time()
    rsa_decrypted = decrypt_rsa(rsa_ciphertext, private_key)
    rsa_decrypt_time = time.time() - start_time

    print(f"\nHasil Dekripsi RSA: {rsa_decrypted}")
    print(f"Waktu dekripsi RSA: {rsa_decrypt_time:.6f} detik")

    # --- Perbandingan Ukuran Ciphertext dan Waktu ---
    print("\n" + "="*50)
    print("PERBANDINGAN ANTARA AES DAN RSA")
    print("="*50)

    print(f"\nUkuran ciphertext AES: {len(aes_ciphertext)} byte")
    print(f"Ukuran ciphertext RSA: {len(rsa_ciphertext)} byte")

    print(f"\nWaktu enkripsi AES: {aes_encrypt_time:.6f} detik")
    print(f"Waktu enkripsi RSA: {rsa_encrypt_time:.6f} detik")
    print(f"\nWaktu dekripsi AES: {aes_decrypt_time:.6f} detik")
    print(f"Waktu dekripsi RSA: {rsa_decrypt_time:.6f} detik")

    # Analisis efisiensi
    print("\n" + "-"*50)
    print("ANALISIS EFISIENSI")
    print("-"*50)
    if aes_encrypt_time < rsa_encrypt_time:
        print("✅ AES lebih cepat dalam enkripsi.")
    else:
        print("⚠️ RSA lebih cepat dalam enkripsi (tidak umum).")

    if aes_decrypt_time < rsa_decrypt_time:
        print("✅ AES lebih cepat dalam dekripsi.")
    else:
        print("⚠️ RSA lebih cepat dalam dekripsi (tidak umum).")

    if len(aes_ciphertext) < len(rsa_ciphertext):
        print("✅ AES menghasilkan ciphertext lebih kecil (untuk teks panjang).")
    else:
        print("⚠️ RSA menghasilkan ciphertext lebih kecil (biasanya tidak benar untuk teks panjang).")

    print("\nKESIMPULAN:")
    print("- AES sangat efisien untuk enkripsi data besar dan cepat.")
    print("- RSA cocok untuk enkripsi kunci atau data kecil karena prosesnya lambat dan ukurannya besar.")
    print("- Dalam praktik nyata, RSA sering digunakan untuk mengenkripsi kunci AES, bukan data langsung.")

if __name__ == "__main__":
    main() 