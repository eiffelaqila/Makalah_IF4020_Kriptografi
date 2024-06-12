from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import hashlib

import base64
import json

import numpy as np
import cv2

class ECDSACryptography:
    def __init__(self):
        pass

    @staticmethod
    def generate_ecdsa_key_pairs():
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key
        return (private_key.to_string(), public_key.to_string())

    def get_private_key_from_file(self, private_key_path):
        with open(private_key_path, 'rb') as f:
            private_key_data = f.read()
        private_key = SigningKey.from_string(private_key_data, curve=SECP256k1)
        public_key = private_key.verifying_key
        return (private_key, public_key)

    def get_public_key_from_file(self, public_key_path):
        with open(public_key_path, 'rb') as f:
            public_key_data = f.read()
        return VerifyingKey.from_string(public_key_data, curve=SECP256k1)

    def sign_data(self, private_key, data):
        print('Signing data...')
        hash_data = hashlib.sha256(data).digest()
        signature = private_key.sign(hash_data)
        return signature

    def verify_signature(self, public_key, signature, data):
        print('Verifying signature...')
        hash_data = hashlib.sha256(data).digest()
        try:
            public_key.verify(signature, hash_data)
            return True
        except ValueError:
            return False

class AESRSACryptography:
    def __init__(self):
        self.ecdsa = ECDSACryptography()

    @staticmethod
    def generate_rsa_key_pairs(key_size=2048):
        private_key = RSA.generate(key_size)
        public_key = private_key.publickey()
        return (private_key.export_key(), public_key.export_key())

    def get_private_key_from_file(self, private_key_path):
        with open(private_key_path, 'rb') as f:
            private_key_data = f.read()
        private_key = RSA.import_key(private_key_data)
        public_key = private_key.publickey()
        return (private_key, public_key)

    def get_public_key_from_file(self, public_key_path):
        with open(public_key_path, 'rb') as f:
            public_key_data = f.read()
        return RSA.import_key(public_key_data)

    def generate_symmetric_key(self):
        return get_random_bytes(16)

    def encrypt_image(self, input_image_path, ds_private_key, other_rsa_public_key):
        with open(input_image_path, 'rb') as f:
            plain_bytes = f.read()

        # AES symmetric key
        symmetric_key = self.generate_symmetric_key()

        # sign the image data using ECDSA private key
        signature = self.ecdsa.sign_data(ds_private_key, plain_bytes)
        print('Concating signature to data...')
        signed_image_bytes = plain_bytes + signature

        # encrypt the image data using AES with the symmetric key
        print('Encrypting data...')
        cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(signed_image_bytes)

        # encrypt the symmetric key using RSA public key of the recipient
        print('Encrypting symmetric key...')
        cipher_rsa = PKCS1_OAEP.new(other_rsa_public_key)
        encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)

        encrypted_data = {
            'enc_image': ciphertext,
            'enc_tag': tag,
            'enc_nonce': cipher_aes.nonce,
            'enc_rsa': encrypted_symmetric_key,
        }

        return encrypted_data

    def decrypt_image(self, encrypted_data, other_ds_public_key, rsa_private_key):
        # decrypt the encrypted symmteric key using RSA private key
        print('Decrypting symmetric key...')
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        decrypted_symmetric_key = cipher_rsa.decrypt(encrypted_data['enc_rsa'])

        # decrypt the image data using AES with the decrypted symmetric key
        print('Decrypting data...')
        cipher_aes = AES.new(decrypted_symmetric_key, AES.MODE_EAX, nonce=encrypted_data['enc_nonce'])
        decrypted_data = cipher_aes.decrypt_and_verify(encrypted_data['enc_image'], encrypted_data['enc_tag'])

        # separate the signature and image data
        signature = decrypted_data[-64:]
        image_data = decrypted_data[:-64]

        # Verify the signature using ECC public key
        is_valid_signature = self.ecdsa.verify_signature(other_ds_public_key, signature, image_data)

        if is_valid_signature:
            print('Signature is valid!')
            return image_data
        else:
            print('Signature is invalid!')
            return None

class Utilities:
    def __init__(self):
        self.aes_rsa_crypto = AESRSACryptography()
        self.ecdsa_crypto = ECDSACryptography()

    def save_rsa_keys(self, private_key_filename, public_key_filename):
        private_key, public_key = self.aes_rsa_crypto.generate_rsa_key_pairs()

        with open(private_key_filename, 'wb') as f:
            f.write(private_key)

        with open(public_key_filename, 'wb') as f:
            f.write(public_key)

        print(f'RSA private key file is written successfully: {private_key_filename}')
        print(f'RSA public key file is written successfully: {public_key_filename}')

    def save_ecdsa_keys(self, private_key_filename, public_key_filename):
        private_key, public_key = self.ecdsa_crypto.generate_ecdsa_key_pairs()

        with open(private_key_filename, 'wb') as f:
            f.write(private_key)

        with open(public_key_filename, 'wb') as f:
            f.write(public_key)
        
        print(f'ECDSA private key file is written successfully: {private_key_filename}')
        print(f'ECDSA public key file is written successfully: {public_key_filename}')

    def save_encrypted_data(self, encrypted_data, output_path='encrypted.txt'):
        encoded_encrypted_data = {
            'enc_image': base64.b64encode(encrypted_data['enc_image']).decode('utf-8'),
            'enc_tag': base64.b64encode(encrypted_data['enc_tag']).decode('utf-8'),
            'enc_nonce': base64.b64encode(encrypted_data['enc_nonce']).decode('utf-8'),
            'enc_rsa': base64.b64encode(encrypted_data['enc_rsa']).decode('utf-8'),
        }
        with open(output_path, 'w') as f:
            f.write(base64.b64encode(json.dumps(encoded_encrypted_data).encode('utf-8')).decode('utf-8'))
    
    def load_encrypted_data(self, encrypted_data_path='encrypted.txt'):
        with open(encrypted_data_path, 'r') as f:
            encoded_encrypted_data = json.loads(base64.b64decode(f.read()))

        # Convert base64 encoded strings back to binary data
        encrypted_data = {
            'enc_image': base64.b64decode(encoded_encrypted_data['enc_image']),
            'enc_tag': base64.b64decode(encoded_encrypted_data['enc_tag']),
            'enc_nonce': base64.b64decode(encoded_encrypted_data['enc_nonce']),
            'enc_rsa': base64.b64decode(encoded_encrypted_data['enc_rsa']),
        }
        
        return encrypted_data

    def save_decrypted_data(self, decrypted_data, output_path='decrypted.png'):
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
    
    def psnr(self, img1_path, img2_path):
        img1 = cv2.imread(img1_path)
        img2 = cv2.imread(img2_path)
        mse = np.mean((img1 - img2) ** 2)
        if mse == 0:
            return float('inf')
        PIXEL_MAX = 255.0
        return 20 * np.log10(PIXEL_MAX / np.sqrt(mse))

if __name__ == '__main__':
    # Example usage:
    aes_rsa_crypto = AESRSACryptography()
    ecdsa_crypto = ECDSACryptography()
    utilities = Utilities()

    print('Available commands:')
    print('1.\tGenerate RSA Key Pairs')
    print('2.\tGenerate ECDSA Key Pairs')
    print('3.\tEncrypt and Sign Image')
    print('4.\tDecrypt and Verify Encrypted Image')
    print('5.\tCompare two images (PSNR)')
    print('6.\tExit')
    command = int(input('Enter command: '))

    encrypted_data = None

    while command > 0 and command < 6:
        if command == 1:
            private_key_filename = input('Enter RSA private key filename: ')
            public_key_filename = input('Enter RSA public key filename: ')
            utilities.save_rsa_keys(private_key_filename, public_key_filename)
        elif command == 2:
            private_key_filename = input('Enter ECDSA private key filename: ')
            public_key_filename = input('Enter ECDSA public key filename: ')
            utilities.save_ecdsa_keys(private_key_filename, public_key_filename)
        elif command == 3:
            rsa_public_key_path = input('Enter other RSA public key path: ')
            rsa_public_key = aes_rsa_crypto.get_public_key_from_file(rsa_public_key_path)

            ecdsa_private_key_path = input('Enter ECDSA private key path: ')
            ecdsa_private_key, ecdsa_public_key = ecdsa_crypto.get_private_key_from_file(ecdsa_private_key_path)

            image_path = input('Enter image path: ')
            encrypted_data = aes_rsa_crypto.encrypt_image(image_path, ecdsa_private_key, rsa_public_key)

            enc_image_path = input('Enter encrypted image path: ')
            utilities.save_encrypted_data(encrypted_data, enc_image_path)
            print(f'Encrypted image is successfully saved to {enc_image_path}')
        elif command == 4:
            rsa_private_key_path = input('Enter RSA private key path: ')
            rsa_private_key, rsa_public_key = aes_rsa_crypto.get_private_key_from_file(rsa_private_key_path)

            ecdsa_public_key_path = input('Enter other ECDSA public key path: ')
            ecdsa_public_key = ecdsa_crypto.get_public_key_from_file(ecdsa_public_key_path)

            enc_image_path = input('Enter encrypted image path: ')
            encrypted_data = utilities.load_encrypted_data(enc_image_path)
            decrypted_data = aes_rsa_crypto.decrypt_image(encrypted_data, ecdsa_public_key, rsa_private_key)
            
            dec_image_path = input('Enter decrypted image path: ')
            utilities.save_decrypted_data(decrypted_data, dec_image_path)
            print(f'Decrypted image is successfully saved to {dec_image_path}')
        elif command == 5:
            original_image_path = input('Enter original image path: ')
            decrypted_image_path = input('Enter decrypted image path: ')
            psnr = utilities.psnr(original_image_path, decrypted_image_path)
            print('PSNR:', psnr)

        print('\nAvailable commands:')
        print('1.\tGenerate RSA Key Pairs')
        print('2.\tGenerate ECDSA Key Pairs')
        print('3.\tEncrypt and Sign Image')
        print('4.\tDecrypt and Verify Encrypted Image')
        print('5.\tCompare Two Images (PSNR)')
        print('6.\tExit')   
        command = int(input('Enter command: '))
