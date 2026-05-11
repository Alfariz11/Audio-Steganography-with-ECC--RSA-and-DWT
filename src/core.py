import os
import zlib
import struct
import numpy as np
import soundfile as sf
from PIL import Image
from reedsolo import RSCodec

# Local modules
from steg import AudioDWT
from crypto.ecc import ECCCrypto
from crypto.rsa import RSACrypto
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES

def generate_audio(output_file, duration=10, sample_rate=44100):
    """Generates a sample sine wave audio file."""
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    audio_data = 0.5 * np.sin(2 * np.pi * 440 * t)
    sf.write(output_file, audio_data, sample_rate)
    print(f"Sample audio file created: {output_file}")
    return output_file

def prepare_payload(message, ecc_recipient_pub_pem, rsa_signer):
    """
    Prepares the payload: Compress -> Encrypt (AES-GCM) -> Encrypt Key (ECC) -> Sign (RSA)
    Returns: Raw bytes of the complete protected package.
    """
    # 1. Compression
    if isinstance(message, str):
        message = message.encode('utf-8')
    compressed_data = zlib.compress(message)
    
    # 2. AES-256-GCM Encryption
    session_key = get_random_bytes(32)  # AES-256
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    encrypted_payload, aes_tag = cipher_aes.encrypt_and_digest(compressed_data)
    aes_nonce = cipher_aes.nonce
    
    # 3. ECC (ECIES) Encryption of Session Key
    ecc = ECCCrypto()
    eph_pub, ecc_ct, ecc_nonce, ecc_tag = ecc.encrypt_session_key(session_key, ecc_recipient_pub_pem)
    
    # 4. RSA Digital Signature
    # We sign the encrypted payload + AES metadata + ECC metadata
    data_to_sign = eph_pub + ecc_ct + ecc_nonce + ecc_tag + aes_nonce + aes_tag + encrypted_payload
    signature = rsa_signer.sign_data(data_to_sign)
    
    # 5. Pack into binary format
    # [EphPubLen 2b][EphPub][ECC_CTLen 2b][ECC_CT][ECC_Nonce 16b][ECC_Tag 16b][RSA_Sig 256b][AES_Nonce 16b][AES_Tag 16b][EncryptedPayload]
    package = struct.pack(">H", len(eph_pub)) + eph_pub
    package += struct.pack(">H", len(ecc_ct)) + ecc_ct
    package += ecc_nonce + ecc_tag
    package += signature # 256 bytes for 2048-bit RSA
    package += aes_nonce + aes_tag
    package += encrypted_payload
    
    return package

def apply_error_correction(data, parity_bytes=32):
    """Applies Reed-Solomon error correction."""
    rsc = RSCodec(parity_bytes)
    return bytes(rsc.encode(data))

def remove_error_correction(data, parity_bytes=32):
    """Decodes Reed-Solomon error correction."""
    rsc = RSCodec(parity_bytes)
    try:
        decoded = rsc.decode(data)[0]
        return bytes(decoded)
    except Exception as e:
        print(f"RS Decoding failed: {e}")
        return None

def embed_message(input_file=None, output_file=None, message=None, alpha=0.001, is_image=False, rs_parity=32):
    """
    Complete embedding workflow.
    """
    os.makedirs('output', exist_ok=True)
    
    if not input_file:
        input_file = 'output/sample.wav'
        if not os.path.exists(input_file):
            generate_audio(input_file)
            
    if not output_file:
        output_file = 'output/stego.wav'

    if message is None:
        return None

    if is_image:
        with open(message, "rb") as f:
            message_data = f.read()
    else:
        message_data = message.encode('utf-8')

    # Initialize cryptos
    ecc = ECCCrypto()
    rsa = RSACrypto()
    
    # Prepare payload
    print("Preparing encrypted payload...")
    package = prepare_payload(message_data, ecc.get_public_key(), rsa)
    
    # Apply Reed-Solomon
    print(f"Applying Reed-Solomon error correction (parity={rs_parity})...")
    rs_package = apply_error_correction(package, rs_parity)
    
    # Convert to bits
    dwt = AudioDWT(wavelet='db2', level=1)
    bits = dwt.bytes_to_bits(rs_package)
    
    # Add header: [RS_Package_Length 4 bytes]
    header = format(len(rs_package), '032b')
    all_bits = header + bits
    
    print(f"Embedding {len(all_bits)} bits into audio...")
    
    # Audio processing
    audio_data, sample_rate = dwt.read_audio(input_file)
    coeffs = dwt.apply_dwt(audio_data)
    
    if len(all_bits) > len(coeffs[1]):
        print(f"Error: Message too large. Capacity: {len(coeffs[1])} bits, Needed: {len(all_bits)} bits.")
        return None
        
    modified_coeffs = dwt.embed_bits_in_coefficients(coeffs, all_bits, alpha=alpha)
    reconstructed_data = dwt.apply_idwt(modified_coeffs)
    
    # Handle stereo
    if len(audio_data.shape) > 1 and audio_data.shape[1] > 1:
        min_len = min(len(reconstructed_data), len(audio_data))
        reconstructed_stereo = np.zeros((min_len, audio_data.shape[1]))
        reconstructed_stereo[:, 0] = reconstructed_data[:min_len]
        for ch in range(1, audio_data.shape[1]):
            reconstructed_stereo[:, ch] = audio_data[:min_len, ch]
        reconstructed_data = reconstructed_stereo
        
    dwt.save_audio(output_file, reconstructed_data, sample_rate)
    
    # Save keys/info for extraction
    info_file = output_file + ".info"
    import json
    info = {
        "rs_parity": rs_parity,
        "ecc_private_key": ecc.get_private_key(),
        "rsa_public_key": rsa.get_public_key(),
        "alpha": alpha,
        "is_image": is_image
    }
    
    with open(info_file, 'w') as f:
        json.dump(info, f)
        
    # Also save keys in a human readable format
    with open(output_file + ".key", 'w') as f:
        f.write("=== ECC PRIVATE KEY (KEEP SECRET) ===\n")
        f.write(ecc.get_private_key())
        f.write("\n\n=== RSA PUBLIC KEY (FOR VERIFICATION) ===\n")
        f.write(rsa.get_public_key())
        f.write("\n\n=== RSA PRIVATE KEY (FOR SIGNING) ===\n")
        f.write(rsa.get_private_key())

    print(f"Success! Stego audio saved to {output_file}")
    return output_file

def extract_message(stego_file, ecc_private_key_pem=None, rsa_public_key_pem=None):
    """
    Complete extraction workflow.
    """
    info_file = stego_file + ".info"
    rs_parity = 32
    alpha = 0.001
    is_image = False
    
    import json
    if os.path.exists(info_file):
        with open(info_file, 'r') as f:
            info = json.load(f)
            rs_parity = info.get("rs_parity", 32)
            alpha = info.get("alpha", 0.001)
            is_image = info.get("is_image", False)
            if not ecc_private_key_pem:
                ecc_private_key_pem = info.get("ecc_private_key")
            if not rsa_public_key_pem:
                rsa_public_key_pem = info.get("rsa_public_key")

    dwt = AudioDWT(wavelet='db2', level=1)
    audio_data, sample_rate = dwt.read_audio(stego_file)
    coeffs = dwt.apply_dwt(audio_data)
    
    # 1. Extract length header (32 bits)
    header_bits = dwt.extract_bits_from_coefficients(coeffs, 32, alpha=alpha)
    rs_package_len = int(header_bits, 2)
    
    # 2. Extract RS package bits
    total_bits_needed = 32 + (rs_package_len * 8)
    all_bits = dwt.extract_bits_from_coefficients(coeffs, total_bits_needed, alpha=alpha)
    rs_package_bits = all_bits[32:]
    rs_package = dwt.bits_to_bytes(rs_package_bits)
    
    # 3. Reed-Solomon Decode
    print("Decoding Reed-Solomon...")
    package = remove_error_correction(rs_package, rs_parity)
    if not package:
        print("Error: Could not recover data even with Reed-Solomon.")
        return None
        
    # 4. Unpack binary format
    try:
        offset = 0
        eph_pub_len = struct.unpack(">H", package[offset:offset+2])[0]
        offset += 2
        eph_pub = package[offset:offset+eph_pub_len]
        offset += eph_pub_len
        
        ecc_ct_len = struct.unpack(">H", package[offset:offset+2])[0]
        offset += 2
        ecc_ct = package[offset:offset+ecc_ct_len]
        offset += ecc_ct_len
        
        ecc_nonce = package[offset:offset+16]
        offset += 16
        ecc_tag = package[offset:offset+16]
        offset += 16
        
        signature = package[offset:offset+256]
        offset += 256
        
        aes_nonce = package[offset:offset+16]
        offset += 16
        aes_tag = package[offset:offset+16]
        offset += 16
        
        encrypted_payload = package[offset:]
        
        # 5. Verify RSA Signature
        print("Verifying RSA signature...")
        data_to_verify = eph_pub + ecc_ct + ecc_nonce + ecc_tag + aes_nonce + aes_tag + encrypted_payload
        rsa = RSACrypto()
        if not rsa.verify_signature(data_to_verify, signature, rsa_public_key_pem):
            print("Warning: RSA signature verification failed! Data might be tampered.")
        else:
            print("RSA signature verified.")
            
        # 6. Decrypt Session Key with ECC
        print("Decrypting session key with ECC...")
        ecc = ECCCrypto()
        ecc.load_key(ecc_private_key_pem)
        session_key = ecc.decrypt_session_key(eph_pub, ecc_ct, ecc_nonce, ecc_tag)
        
        # 7. Decrypt Payload with AES-GCM
        print("Decrypting payload with AES-GCM...")
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=aes_nonce)
        compressed_data = cipher_aes.decrypt_and_verify(encrypted_payload, aes_tag)
        
        # 8. Decompress
        original_data = zlib.decompress(compressed_data)
        
        if is_image:
            output_img = "output/extracted_image.png"
            with open(output_img, "wb") as f:
                f.write(original_data)
            print(f"Extracted image saved to {output_img}")
            return output_img
        else:
            message = original_data.decode('utf-8')
            print(f"Extracted message: {message}")
            return message
            
    except Exception as e:
        print(f"Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return None
