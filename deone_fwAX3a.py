# pylint: disable:E265
# pylint: disable=C0103
# pylint: disable=C0111
# -------------------------------------------------------------------------
# Name:           Crypto
# Purpose:       Vernam cipher with hex output module
#
# Author:       Michael M. Yazdani
#
# Created:       03/05/201
# Copyright:   (c) Michael M. Yazdani 2013
# Licence:       N/A
# -------------------------------------------------------------------------
# pylint: enable:E265
import random
random.seed()


def csr(x):
    if x % 2 == 1:
        return (x >> 1) + 64
    elif x % 2 == 0:
        return x >> 1


def csl(x):
    if x < 64:
        return x << 1
    else:
        return ((x - 64) << 1) + 1


class LFSR:

    def __init__(self, seed, nbits):
        self.seed = seed
        self.nbits = nbits

    def lfsr2(self):
        sr = self.seed
        while True:
            xor = 1
            for t in (1, 2, 3):
                if (sr & (1 << (t - 1))) != 0:
                    xor ^= 1
            sr = (xor << self.nbits - 1) + (sr >> 1)
            yield sr
            if sr == self.seed:
                break

    def lfsr(self, msg):
        register = [x for x in self.lfsr2()]
        out = ''
        for char in range(len(msg)):
            out += hex(ord(msg[char]) ^ register[char % len(register)]) + ' '
        return out

    def key_out(self, key):
        key = key.split(' ')
        out = ''
        register = list(self.lfsr2())
        del key[-1]
        for n in range(0, len(key)):
            out += chr(int(key[n], 16) ^ register[n % len(register)])
        return out


class Crypto:

    def __init__(self, name, msg, seed):
        self.decoded = ""
        self.encoded = ""
        self.alphas = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
        ,.?\"'()[]{}1234567890<>;:!@#$%^&*`~/\\-=_+ "
        self.name = name
        self.msg = msg
        self.feedback = LFSR(seed, 8)
        if not(self.name == 'gen'):
            stream = open("keys/" + self.name)
            if (stream):
                self.key = stream.read()
                stream.close()
            else:
                print(
                    "Error, key not found, make sure its in the key folder\
                    and you spelled it right")
                stream.close()

    def update(self, msg):
        self.msg = msg

    def lfsr_key_in(self):
        return self.feedback.lfsr(self.key)

    def lfsr_key_out(self):
        return self.feedback.key_out(self.key)

    def reset_key(self):
        return self.lfsr_key_out()

    def gen_key(self, name):
        self.key = ""
        used = [False for _ in range(len(self.alphas) + 1)]
        check = []
        for _ in range(len(self.alphas)):
            var = True
            while var:
                num = random.randint(0, len(self.alphas) - 1)
                if used[num] is False:
                    check.append(num)
                    var = False
            used[num] = True
            self.key += self.alphas[num]
        check = sorted(check)
        print(check)
        print("New key: " + self.key)
        stream = open("keys/" + name, mode='w')
        self.key = self.lfsr_key_in()
        stream.write(self.key)
        stream.close()

    def get_key(self):
        stream = open("keys/" + self.name)
        if (stream):
            self.key = stream.read()
            stream.close()
            return self.key
        else:
            print(
                "Error, key not found, make sure its in the key folder and\
                you spelled it right")
            stream.close()

    def In(self):
        encode = self.msg
        self.encoded = ""
        key = self.lfsr_key_out()
        for x in range(0, len(encode)):
            self.encoded += hex(
                csl(csr(ord(key[x % len(key)])) ^ ord(encode[x]))) + " "
        return self.encoded

    def Out(self):
        self.encoded = self.msg.split(' ')
        self.decoded = ""
        key = self.lfsr_key_out()
        del self.encoded[len(self.encoded) - 1]
        for x in range(0, len(self.encoded)):
            self.decoded += chr(
                csr(int(self.encoded[x], base=16)) ^ csr(ord(key[x % len(key)]))
            )
        return self.decoded


class CryptIO:

    def __init__(self, fin, fout):
        self.file = open(fin)
        self.file2 = open(fout, 'w')

    def close(self):
        self.file.close()
        self.file2.close()

    def In(self, key, seed):
        crypto = Crypto(key, '', seed)
        self.file2.write(crypto.lfsr_key_in() + '\n')
        self.file2.write('begin' + '\n')
        for line in self.file:
            crypto.update(line)
            fin = crypto.In()
            self.file2.write(fin + '\n')
        self.file2.write('\n')
        self.close()
        del crypto

    def Out(self, seed):
        check = False
        shift = LFSR(seed, 8)
        for line in self.file:
            if (not check) and (line != 'begin\n'):
                print(line)
                crypto = Crypto('gen', '', seed)
                crypto.key = shift.key_out(line)
            elif check:
                crypto.update(line)
                fout = crypto.Out()
                print(line)
                print(fout)
                self.file2.write(fout)
            elif line == 'begin\n':
                check = True
                continue

        self.close()

if __name__ == '__main__':
    while True:
        key, message, seed = input('Key, message, seed: ').split(', ')
        type = input('Encrypt or Decrypt? ').lower()
        c = Crypto(key, message, int(seed))
        if type == 'encrypt':
            print(c.In())
        elif type == 'decrypt':
            print(c.Out())
