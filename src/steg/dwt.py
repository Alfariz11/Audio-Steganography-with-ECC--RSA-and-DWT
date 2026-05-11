import numpy as np
import pywt
import soundfile as sf

class AudioDWT:
    """
    Handles audio steganography using Discrete Wavelet Transform (DWT).
    Optimized for binary data embedding.
    """
    def __init__(self, wavelet='db2', level=1):
        self.wavelet = wavelet
        self.level = level
    
    def read_audio(self, file_path):
        data, sample_rate = sf.read(file_path)
        return data, sample_rate
    
    def save_audio(self, file_path, data, sample_rate):
        sf.write(file_path, data, sample_rate)
    
    def apply_dwt(self, audio_data):
        # Use first channel for DWT if stereo
        if len(audio_data.shape) > 1 and audio_data.shape[1] > 1:
            data_for_dwt = audio_data[:, 0]
        else:
            data_for_dwt = audio_data
        
        coeffs = pywt.wavedec(data_for_dwt, self.wavelet, level=self.level)
        return coeffs
    
    def apply_idwt(self, coeffs):
        return pywt.waverec(coeffs, self.wavelet)
    
    def embed_bits_in_coefficients(self, coeffs, bits, alpha=0.001):
        """
        Embeds bits into the detail coefficients using Quantization Index Modulation (QIM).
        """
        detail_coeffs = coeffs[1].copy()
        modified_coeffs = list(coeffs)
        
        if len(bits) > len(detail_coeffs):
            raise ValueError(f"Payload too large. Capacity: {len(detail_coeffs)} bits, needed: {len(bits)} bits.")
        
        # QIM embedding
        for i, bit in enumerate(bits):
            coeff = detail_coeffs[i]
            # Quantize based on alpha
            # If bit is '1', move to nearest (2k+1)*alpha
            # If bit is '0', move to nearest 2k*alpha
            
            step = 2 * alpha
            quantized = round(coeff / step) * step
            
            if bit == '1':
                # Shift to the nearest odd multiple of alpha
                if (round(coeff / step) % 2) == 0: # currently at even
                    if coeff >= quantized:
                        detail_coeffs[i] = quantized + alpha
                    else:
                        detail_coeffs[i] = quantized - alpha
                else: # currently at odd
                    detail_coeffs[i] = quantized
            else:
                # Shift to the nearest even multiple of alpha
                if (round(coeff / step) % 2) != 0: # currently at odd
                    if coeff >= quantized:
                        detail_coeffs[i] = quantized + alpha
                    else:
                        detail_coeffs[i] = quantized - alpha
                else: # currently at even
                    detail_coeffs[i] = quantized
                    
        modified_coeffs[1] = detail_coeffs
        return modified_coeffs
    
    def extract_bits_from_coefficients(self, coeffs, num_bits, alpha=0.001):
        """
        Extracts bits from detail coefficients using QIM detection.
        """
        detail_coeffs = coeffs[1]
        extracted_bits = []
        
        step = 2 * alpha
        for i in range(min(num_bits, len(detail_coeffs))):
            coeff = detail_coeffs[i]
            # Determine if it's closer to even or odd multiple of alpha
            if (round(coeff / alpha) % 2) == 0:
                extracted_bits.append("0")
            else:
                extracted_bits.append("1")
        
        return "".join(extracted_bits)
    
    def bits_to_bytes(self, bits):
        """Converts bit string to bytes."""
        # Ensure bits is a multiple of 8
        if len(bits) % 8 != 0:
            bits = bits.ljust((len(bits) + 7) // 8 * 8, '0')
            
        bytes_list = []
        for i in range(0, len(bits), 8):
            bytes_list.append(int(bits[i:i+8], 2))
        return bytes(bytes_list)
    
    def bytes_to_bits(self, data):
        """Converts bytes to bit string."""
        return "".join(format(b, '08b') for b in data)
