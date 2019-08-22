#!/usr/bin/python
# coding=utf-8

__author__ = 'Simon Charest'
__copyright__ = 'Copyright 2019, SLCIT inc.'
__credits__ = [
    'Réjean Thiboutot',
    'Tutorials Overflow',
    'Guillaume Veck'
]
__email__ = 'simoncharest@gmail.com'
__license__ = 'GNU'
__maintainer__ = 'Simon Charest'
__project__ = 'PyCrypt'
__status__ = 'Developement'
__version__ = '1.0.0'

"""
This app will encrypt a string, recursively, using as many keys as needed, salting the input string on every pass.

Supported AES modes:
    MODE_CBC (Cipher Block Chaining),
    MODE_CFB (Cipher Feedback),
    MODE_EAX (Encrypt-then-Authenticate-then-Translate),
    MODE_ECB (Electronic Code Book)
    MODE_GCM (Galois/Counter Mode),
    MODE_OFB (Output Feedback),
    MODE_SIV (Synthetic Initialization Vector)

Unsupported AES modes:
    MODE_CCM (Counter with CBC-MAC),
    MODE_CTR (Counter),
    MODE_OCB (Offset Codebook Mode),
    MODE_OPENPGP (Open Pretty Good Privacy)

Requirement: pip install pycryptodome

Sources:
    Tutorials Overflow - https://tutorialsoverflow.com/python-encryption-and-decryption/
    PyCryptodome - https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
"""

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import sys

# Global constants definitions
USAGE = 'Usage:\n' \
        '  python pycrypt.py ["string"] ["key1,keyN"] ["salt"], [CBC | CFB | EAX | ECB | GCM | OFB | SIV]\n' \
        'Examples:\n' \
        '  python pycrypt.py HelloWorld!\n' \
        '  python pycrypt.py "Hello World!" "this is my secret key"\n' \
        '  python pycrypt.py "Hello World!" "this is my secret key" "this is a salt"\n' \
        '  python pycrypt.py "Hello World!" "this is my secret key" "this is a salt" SIV'
ENCODING = 'utf8'
AES_MODE_DEFAULT = AES.MODE_SIV
_256_BITS_BLOCK_SIZE = [AES.MODE_ECB, AES.MODE_SIV]
_128_BITS_BLOCK_SIZE = [AES.MODE_ECB, AES.MODE_SIV]
_16_BITS_BLOCK_SIZE = [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_EAX, AES.MODE_ECB, AES.MODE_GCM, AES.MODE_OFB, AES.MODE_SIV]
INITIALIZATION_VECTOR = [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_EAX, AES.MODE_GCM, AES.MODE_OFB]

# AES modes using MAC tags (digest and verify)
MAC_TAG = [AES.MODE_EAX, AES.MODE_GCM, AES.MODE_SIV]


def main():
    # User defined values
    string = 'Hello World!'
    keys = ['my_s3cr3t_k3y_#1', 'my_s3c0nd_s3cr3t_k3y']
    salt = 'Why so salty?'
    aes_mode = AES_MODE_DEFAULT

    # Manage input arguments
    if intersect(['--help', '-h', '/?'], sys.argv):
        print(USAGE)
        exit()

    elif len(sys.argv) == 5:
        string = sys.argv[1]
        keys = sys.argv[2].split(',')
        salt = sys.argv[3]
        aes_mode = get_aes_mode(sys.argv[4])

    elif len(sys.argv) == 4:
        string = sys.argv[1]
        keys = sys.argv[2].split(',')
        salt = sys.argv[3]

    elif len(sys.argv) == 3:
        string = sys.argv[1]
        keys = sys.argv[2].split(',')

    elif len(sys.argv) == 2:
        string = sys.argv[1]

    elif len(sys.argv) == 1:
        pass

    else:
        print(USAGE)
        exit()

    # Create a cipher per key and add them to a list
    ciphers = get_ciphers(keys)

    # Encrypt recursively, using each cipher
    string, mac_tags = encrypt_recursively(ciphers, string, salt, aes_mode)

    # Display encrypted string
    print(string)

    # Decrypt recursively, using each cipher
    string = decrypt_recursively(ciphers, string, salt, aes_mode, mac_tags)

    # Display decrypted string
    print(string)


class AESCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode(ENCODING)).digest()

    def encrypt(self, string, salt='', aes_mode=AES_MODE_DEFAULT, mac_tags=[]):
        # Add salt
        string = add(string, salt)

        # Create cipher
        block_size = get_block_size(aes_mode)
        initialization_vector = ''

        if aes_mode in INITIALIZATION_VECTOR:
            initialization_vector = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, aes_mode, initialization_vector)

        else:
            cipher = AES.new(self.key, aes_mode)

        # Encode string to UTF-8
        string = string.encode(ENCODING)

        # Add padding to string
        string = pad(string, block_size)

        # Encrypt string
        if aes_mode in MAC_TAG:
            string, mac_tag = cipher.encrypt_and_digest(string)
            mac_tags.append(mac_tag)

        else:
            string = cipher.encrypt(string)

        if initialization_vector:
            string = initialization_vector + string

        # Encode string to Base64
        string = base64.b64encode(string)

        # Reverse string (obfuscate)
        string = reverse(string)

        # Convert bytes to a UTF-8 encoded string
        string = string.decode(ENCODING)

        return string, mac_tags

    def decrypt(self, string, salt='', aes_mode=AES_MODE_DEFAULT, mac_tag=b''):
        # Reverse string (unobfuscate)
        string = reverse(string)

        # Decode string
        string = base64.b64decode(string)

        # Create cipher
        block_size = get_block_size(aes_mode)
        encrypted_string = string

        if aes_mode in INITIALIZATION_VECTOR:
            initialization_vector = string[:block_size]
            cipher = AES.new(self.key, aes_mode, initialization_vector)
            encrypted_string = string[block_size:]

        else:
            cipher = AES.new(self.key, aes_mode)

        # Decrypt string
        if aes_mode in MAC_TAG:
            string = cipher.decrypt_and_verify(encrypted_string, mac_tag)

        else:
            string = cipher.decrypt(encrypted_string)

        # Unpad string
        string = unpad(string, block_size)

        # Convert bytes to a UTF-8 encoded string
        string = string.decode(ENCODING)

        # Remove salt
        string = remove(string, salt)

        return string


def intersect(list1, list2):
    return [element for element in list1 if element in list2]


def get_aes_mode(argument):
    aes_mode = AES_MODE_DEFAULT

    if argument == 'CBC':
        aes_mode = AES.MODE_CBC

    elif argument == 'CFB':
        aes_mode = AES.MODE_CFB

    elif argument == 'EAX':
        aes_mode = AES.MODE_EAX

    elif argument == 'ECB':
        aes_mode = AES.MODE_ECB

    elif argument == 'GCM':
        aes_mode = AES.MODE_GCM

    elif argument == 'OFB':
        aes_mode = AES.MODE_OFB

    elif argument == 'SIV':
        aes_mode = AES.MODE_SIV

    return aes_mode


def get_ciphers(keys):
    """ Create a cipher per key and add them to a list """
    ciphers = []

    for key in keys:
        ciphers.append(AESCipher(key))

    return ciphers


def encrypt_recursively(ciphers, string, salt='', aes_mode=AES_MODE_DEFAULT):
    """ Encrypt recursively, using each cipher and MAC tags as needed """
    mac_tags = []

    for cipher in ciphers:
        string, mac_tags = cipher.encrypt(string, salt, aes_mode, mac_tags)

    return string, mac_tags


def decrypt_recursively(ciphers, string, salt='', aes_mode=AES_MODE_DEFAULT, mac_tags=[]):
    """ Decrypt recursively, using each cipher and MAC tags as needed """
    t = len(ciphers) - 1

    # Loop, stepping back, on ciphers and MAC tags
    for cipher in reversed(ciphers):
        mac_tag = b''

        if aes_mode in MAC_TAG:
            mac_tag = mac_tags[t]

        string = cipher.decrypt(string, salt, aes_mode, mac_tag)
        t -= 1

    return string


def get_block_size(aes_mode):
    block_size = 16

    if aes_mode in _256_BITS_BLOCK_SIZE:
        block_size = 256

    elif aes_mode in _128_BITS_BLOCK_SIZE:
        block_size = 128

    return block_size


def add(string, salt):
    string += salt

    return string


def remove(string, salt):
    return string.replace(salt, '')


def reverse(string):
    return string[::-1]


if __name__ == '__main__':
    main()
