from Crypto.Cipher import AES, Blowfish

__author__ = 'khanhnnvn@gmail.com'
__url__ = ''

class AESOracle:
    def __init__(self, iv, key='Sixteen byte key'):
        self.iv = iv
        self.key = key

    def do_oracle(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plaintext = cipher.decrypt(ciphertext)
        padding_len = ord(plaintext[-1])
        return plaintext[-padding_len:] == chr(padding_len) * padding_len

class BlowfishOracle:
    def __init__(self, iv, key='An arbitrarily long key'):
        self.iv = iv
        self.key = key

    def do_oracle(self, ciphertext):
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        padding_len = ord(plaintext[-1])
        return plaintext[-padding_len:] == chr(padding_len) * padding_len
