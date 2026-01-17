
import os
import sys
# Add the current directory to sys.path so we can import from toyecc and mikro
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from toyecc import getcurvebyname, ECPrivateKey, Tools

def generate_keys():
    # 1. Generate Custom License Keys (Curve25519)
    # Used for KCDSA signing of license
    curve_25519 = getcurvebyname('Curve25519')
    priv_license = ECPrivateKey.generate(curve_25519)
    
    # Private key as LE bytes of the scalar
    priv_license_bytes = Tools.inttobytes_le(priv_license.scalar, 32)
    # Public key as LE bytes of the x-coordinate
    pub_license_bytes = Tools.inttobytes_le(int(priv_license.pubkey.point.x), 32)

    print("# Custom License Keys (Curve25519)")
    print(f"export CUSTOM_LICENSE_PRIVATE_KEY={priv_license_bytes.hex().upper()}")
    print(f"export CUSTOM_LICENSE_PUBLIC_KEY={pub_license_bytes.hex().upper()}")
    print("")

    # 2. Generate Custom NPK Sign Keys (Ed25519)
    # Used for EdDSA signing of NPK
    curve_ed25519 = getcurvebyname('Ed25519')
    # MUST use eddsa_generate to ensure seed is set for EdDSA operations
    priv_npk = ECPrivateKey.eddsa_generate(curve_ed25519)
    
    # Private key is the seed
    priv_npk_bytes = priv_npk.eddsa_encode() 
    # Public key is the compressed point (EdDSA format)
    pub_npk_bytes = priv_npk.pubkey.eddsa_encode()

    print("# Custom NPK Sign Keys (Ed25519)")
    print(f"export CUSTOM_NPK_SIGN_PRIVATE_KEY={priv_npk_bytes.hex().upper()}")
    print(f"export CUSTOM_NPK_SIGN_PUBLIC_KEY={pub_npk_bytes.hex().upper()}")

if __name__ == "__main__":
    generate_keys()
