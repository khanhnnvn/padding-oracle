#!/usr/bin/python
from Crypto.Cipher import AES, Blowfish
from Crypto import Random
import struct

__author__ = 'khanhnnvn@gmail.com'
__url__ = ''

def pad(plaintext, bs):
    padding_len = bs - divmod(len(plaintext), bs)[1]
    padding = [padding_len] * padding_len
    padding = struct.pack('b' * padding_len, *padding)
    return plaintext + padding

def AESEncrypt(plaintext):
    key = b'Sixteen byte key'
    iv = Random.new().read(AES.block_size)
    print 'iv: %s' % iv.encode('hex')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(plaintext)
    return ciphertext.encode('hex')

def BlowfishEncrypt(plaintext):
    key = b'An arbitrarily long key'
    iv = Random.new().read(Blowfish.block_size)
    print 'iv: %s' % iv
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(plaintext)
    return ciphertext.encode('hex')

if __name__ == '__main__':
    plaintext = 'Yeah, well done. Keep calm and defeat more ciphertext'
    ptext = pad(plaintext, AES.block_size)
    print AESEncrypt(ptext)
