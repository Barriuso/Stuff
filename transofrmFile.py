#!/usr/bin/python
#
# Author: Arno0x0x, Twitter: @Arno0x0x
#

import argparse
from Crypto.Cipher import AES
import pyscrypt
from base64 import b64encode
from os import urandom
from string import Template
import os

#=====================================================================================
# Crypto functions
#=====================================================================================
#------------------------------------------------------------------------
# XOR encryption
#------------------------------------------------------------------------
def xor(data, key):
    """	data as a bytearray
        key as a string
    """

    l = len(key)
    keyAsInt = list(map(ord, key))
    return bytes(bytearray((
        (data[i] ^ keyAsInt[i % l]) for i in range(0,len(data))
    )))

#------------------------------------------------------------------------
# Class providing RC4 encryption functions
#------------------------------------------------------------------------
class RC4:
    def __init__(self, key = None):
        self.state = list(range(256)) # initialisation de la table de permutation
        self.x = self.y = 0 # les index x et y, au lieu de i et j

        if key is not None:
            self.key = key
            self.init(key)

    # Key schedule
    def init(self, key):
        for i in range(256):
            self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    # Encrypt binary input data
    def binaryEncrypt(self, data):
        output = [None]*len(data)
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = chr((data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF]))
        return ''.join(output)

#------------------------------------------------------------------------
# AES-CBC Encryption
#------------------------------------------------------------------------
def pad(s):
    """PKCS7 padding"""
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesEncrypt(data, key):
    """Encrypts data with the provided key.
    Returns the 16 bytes IV used and the encrypted data
    """

    # Generate a crypto secure random Initialization Vector
    iv = urandom(AES.block_size)

    # Perform PKCS7 padding so that data is a multiple of the block size
    data = pad(data)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv,cipher.encrypt(bytes(data))

#=====================================================================================
# Output format functions
#=====================================================================================
def chunks(s, n):
    """
    Author: HarmJ0y, borrowed from Empire
    Generator to split a string s into chunks of size n.
    """
    for i in range(0, len(s), n):
        yield s[i:i+n]

def formatCPP(data):
    """data as a string representation"""
    temp = "\\x"
    temp += "\\x".join(format(ord(b),'02x') for b in str(data))
    result = "unsigned char data[] = \"" + temp + "\";"
    return result

def formatCSharp(data):
    """data as a string representation"""
    temp = '0x'
    temp += ',0x'.join(format(ord(b),'02x') for b in str(data))
    result = "byte[] data = new byte[] { " + temp + " };"
    return result

def formatPy(data):
    """data as a string representation"""
    temp = '\\x'
    temp += '\\x'.join(format(ord(b),'02x') for b in str(data))
    result = "data = (\"" + temp + "\")"
    return result

def formatVBA(data):
    """data as a string representation"""
    temp = ''
    for chunk in chunks(data, 80):
        temp += ','.join(format(ord(b)) for b in str(chunk))
        temp += ', _\n'

    result = "Data = Array(" + temp[0:-4] + ")"
    return result

def formatVBA2(data):
    """data as a string representation"""
    temp = '&H'
    temp += '&H'.join(format(ord(b),'02X') for b in str(data))

    result = temp
    return result

def formatXLM(data):
    """data as a string representation"""
    temp = ''
    for chunk in chunks(data, 255):
        temp += '='
        for b in chunk:
            temp += 'CHAR({})&'.format(ord(b))
        temp = temp[0:-1] + '\r\n'

    return temp

#=====================================================================================
# Helper functions
#=====================================================================================
def color(string, color=None):
    """
    Author: HarmJ0y, borrowed from Empire
    Change text color for the Linux terminal.
    """
    
    attr = []
    
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        # bold
        attr.append('1')
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

#======================================================================================================
#											MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
    #------------------------------------------------------------------------
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="File to transform", dest="inputFileName")
    parser.add_argument("-e", "--encrypt", help="Optionnal type of encryption to algorithm to use", dest="cryptoAlgorithm", choices=['xor','aes', 'rc4'])
    parser.add_argument("-k", "--key", help="Key used to encrypt the shellcode", dest="key")
    parser.add_argument("-f", "--format", help="Output format (base64, C++, C#, Python, VBA, VB-Body, XLM)", dest="format", choices=['b64','cpp','cs','py','vba','vba2','xlm'])
    parser.add_argument("-o", "--output", help="Output file", dest="outputFileName")
    args = parser.parse_args()


    if args.inputFileName:
        #------------------------------------------------------------------------
        # Open input file and read all bytes from it
        try:
            with open(args.inputFileName) as fileHandle:
                fileBytes = bytearray(fileHandle.read(),'utf-8')
                fileHandle.close()
                print(color("[*] File [{}] successfully loaded !".format(args.inputFileName)))
        except IOError:
            print(color("[!] Could not open or read file [{}]".format(args.inputFileName)))
            quit()

        print(color("[*] Input length: [{}] bytes".format(len(fileBytes))))

        #------------------------------------------------------------------------
        # First transformation: should the input file be encrypted ?
        if args.cryptoAlgorithm:
            if not args.key:
                print(color("[!] Missing argument 'key' for the encryption algorithm"))
                quit()

            if args.cryptoAlgorithm == 'xor':
                print(color("[*] Performing XOR encryption of the input file with key [{}]".format(args.key)))
                transformed1 = xor(fileBytes, args.key)
                print(color("[+] File XOR encrypted"))

            elif args.cryptoAlgorithm == 'aes':
                # Derive a 16 bytes (128 bits) master key from the provided key
                key = pyscrypt.hash(args.key, "saltmegood", 1024, 1, 1, 16)
                print(color("[*] Performing AES encryption of the input file"))
                iv, transformed1 = aesEncrypt(fileBytes, key)
                print(color("[+] File AES encrypted with IV [{}] and Key [{}]".format(b64encode(iv),b64encode(key))))

            elif args.cryptoAlgorithm == 'rc4':
                rc4Encryptor = RC4(args.key)
                print(color("[*] Performing RC4 encryption of the input file with key [{}]".format(args.key)))
                transformed1 = rc4Encryptor.binaryEncrypt(fileBytes)
                print(color("[+] File RC4 encrypted"))

        else:
            print(color("[*] Bypassing encryption"))
            transformed1 = str(fileBytes)

        #------------------------------------------------------------------------
        # Second transformation
        if args.format:
            if args.format == 'b64':
                print(color("[*] Formating output as base64 encoding"))
                transformed2 = b64encode(transformed1)

            elif args.format == 'cpp':
                print(color("[*] Formating output as a C++ variable representation"))
                transformed2 = formatCPP(transformed1)

            elif args.format == 'cs':
                print(color("[*] Formating output as a C# variable representation"))
                transformed2 = formatCSharp(transformed1)

            elif args.format == 'py':
                print(color("[*] Formating output as a Python variable representation"))
                transformed2 = formatPy(transformed1)

            elif args.format == 'vba':
                print(color("[*] Formating output as VBA variable representation"))
                transformed2 = formatVBA(transformed1)

            elif args.format == 'vba2':
                print(color("[*] Formating output as VB body representation"))
                transformed2 = formatVBA2(transformed1)

            elif args.format == 'xlm':
                print(color("[*] Formating output as XLM cells representation"))
                transformed2 = formatXLM(transformed1)

            print(color("[+] Output formating done"))

        else:
            transformed2 = transformed1

        #------------------------------------------------------------------------
        # Finally, write output to stdout of to a file
        if args.outputFileName:
            try:
                with open(args.outputFileName, 'w+') as fileHandle:
                    fileHandle.write(transformed2)
                    fileHandle.close()
                    print(color("[+] Output file [{}] saved successfully".format(args.outputFileName)))
            except IOError:
                print(color("[!] Could not write file [{}]".format(args.outputFileName)))
        else:
            print(transformed2)

        print(color("[*] Output length: [{}]".format(len(transformed2))))

    else:
        parser.print_help()
        print(color("\nExample: ./{} -i myFile -e xor -k myKey -cs -o outputFile\n".format(os.path.basename(__file__)),"green"))
