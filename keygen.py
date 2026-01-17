
import os
import sys
import struct
# Menambahkan path agar bisa import mikro
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mikro import (
    mikro_softwareid_decode, 
    mikro_kcdsa_sign, 
    mikro_encode, 
    mikro_base64_encode,
    MIKRO_LICENSE_HEADER,
    MIKRO_LICENSE_FOOTER
)

def generate_license(software_id, private_key_hex, level=6):
    # 1. Decode Software ID (String -> Int)
    sid_int = mikro_softwareid_decode(software_id)
    
    # 2. Persiapkan Payload Lisensi
    # Format biasanya: [Level (1 byte)][Software ID (4 bytes LE)]
    # Namun MikroTik v6/v7 sering menggunakan format 16 byte payload untuk tanda tangan
    payload = struct.pack('<BI', level, sid_int).ljust(16, b'\x00')
    
    # 3. Sign Payload menggunakan KCDSA (Private Key Anda)
    private_key = bytes.fromhex(private_key_hex)
    signature = mikro_kcdsa_sign(payload, private_key)
    
    # 4. Gabungkan Payload dan Signature
    full_binary = payload + signature
    
    # 5. Mikro Encode (Custom Scrambling MikroTik)
    encoded_binary = mikro_encode(full_binary)
    
    # 6. Base64 Encode (Custom Table)
    b64_str = mikro_base64_encode(encoded_binary)
    
    # 7. Print Hasil dalam Format Header/Footer
    print(MIKRO_LICENSE_HEADER)
    # Split base64 ke beberapa baris (biasanya per 64 karakter)
    for i in range(0, len(b64_str), 64):
        print(b64_str[i:i+64])
    print(MIKRO_LICENSE_FOOTER)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 keygen.py <SoftwareID> <PrivateKeyHex>")
        print("Example: python3 keygen.py DJ21-EIQP 9DBC845E9018537810FDAE62824322EEE1B12BAD81FCA28EC295FB397C61CE0B")
        sys.exit(1)
        
    sid = sys.argv[1]
    pk_hex = sys.argv[2]
    generate_license(sid, pk_hex)
