#!/usr/bin/env python
from passlib.crypto.digest import pbkdf2_hmac
import hashlib
import argparse
import os
from struct import Struct
from Crypto.Cipher import AES
import base64
from Crypto import Random
from Crypto.Util.Padding import unpad
import struct

PBKDF2_ALGO = "sha1"
HASH_COUNT = 2000
IV_LEN_BYTES = 16
SCRYPT_ADDED_MINOR = 2
KDF_PBKDF = 1
KDF_SCRYPT = 2
KDF_SCRYPT_KEYMASTER_UNPADDED = 3
KDF_SCRYPT_KEYMASTER_BADLY_PADDED = 4
KDF_SCRYPT_KEYMASTER = 5
KDF_NAMES = dict()
KDF_NAMES[KDF_PBKDF] = "PBKDF2"
KDF_NAMES[KDF_SCRYPT] = "scrypt"
KDF_NAMES[KDF_SCRYPT_KEYMASTER_UNPADDED] = "scrypt+keymaster (padded)"
KDF_NAMES[KDF_SCRYPT_KEYMASTER_BADLY_PADDED] = "scrypt+keymaster (badly padded)"
KDF_NAMES[KDF_SCRYPT_KEYMASTER] = "scrypt+keymaster"
CRYPT_TYPES = ('password', 'default', 'pattern', 'PIN')
BLOCK_SIZE = 16


def parse_footer(footer_file):
    assert (os.path.getsize(footer_file) >= 16384), f"Footer file {footer_file} must be at least 16384 bytes"
    footer = open(footer_file, 'rb').read()

    s = Struct('<' + 'L H H')
    ftrMagic, majorVersion, minorVersion = s.unpack_from(footer)
    if minorVersion < SCRYPT_ADDED_MINOR:
        s = Struct('<' + 'L H H L L L L L L L 64s L 48s 16s')
        (ftrMagic, majorVersion, minorVersion,
         ftrSize, flags, keySize, spare1,
         fsSize1, fsSize2, failedDecrypt, cryptoType,
         spare2, cryptoKey, cryptoSalt) = s.unpack_from(footer)

        cryptoKey = cryptoKey[0:keySize]
    elif minorVersion == SCRYPT_ADDED_MINOR:
        s = Struct('<' + 'L H H L L L L L L L 64s L 48s 16s 2Q L B B B B')
        (ftrMagic, majorVersion, minorVersion, ftrSize,
         flags, keySize, spare1, fsSize1, fsSize2,
         failedDecrypt, cryptoType, spare2, cryptoKey,
         cryptoSalt, persistDataOffset1, persistDataOffset2,
         persistDataSize, kdf, N_factor, r_factor,
         p_factor) = s.unpack_from(footer)

        cryptoKey = cryptoKey[0:keySize]
        N = 1 << N_factor
        r = 1 << r_factor
        p = 1 << p_factor
    else:
        s = Struct('<' + 'L H H L L L L Q L 64s L 48s 16s 2Q L B B B B Q 32s 2048s L 32s')
        (ftrMagic, majorVersion, minorVersion, ftrSize,
         flags, keySize, crypt_type, fsSize,
         failedDecrypt, cryptoType, spare2, cryptoKey,
         cryptoSalt, persistDataOffset1, persistDataOffset2,
         persistDataSize, kdf, N_factor, r_factor,
         p_factor,
         encrypted_upto,
         hash_first_block,
         km_blob, km_blob_size,
         scrypted_intermediate_key) = s.unpack_from(footer)

    print('| -------------------------')
    print("| Android FDE crypto footer")
    print('| -------------------------')
    print('| Magic              :', "0x%0.8X" % ftrMagic)
    print('| Major Version      :', majorVersion)
    print('| Minor Version      :', minorVersion)
    print('| Footer Size        :', ftrSize, "bytes")
    print('| Flags              :', "0x%0.8X" % flags)
    print('| Key Size           :', keySize * 8, "bits")
    # print('| Password Type      :', f'{spare1} ({CRYPT_TYPES[spare1]})')
    print('| Failed Decrypts    :', failedDecrypt)
    print('| Crypto Type        :', ''.join(map(chr, cryptoType)))
    print('| Encrypted Key      :', "0x" + cryptoKey.hex())
    print('| Salt               :', "0x" + cryptoSalt.hex())
    if minorVersion >= SCRYPT_ADDED_MINOR:
        if kdf in KDF_NAMES.keys():
            print('KDF                : %s' % KDF_NAMES[kdf])
        else:
            print('KDF                :', ("unknown (%d)" % kdf))
            print('N_factor           :', "%u	(N=%u)" % (N_factor, N))
            print('r_factor           :', "%u	(r=%u)" % (r_factor, r))
            print('p_factor           :', "%u	(p=%u)" % (p_factor, p))
    if minorVersion >= KDF_SCRYPT_KEYMASTER_UNPADDED:
        print('crypt type         : %s' % CRYPT_TYPES[crypt_type])
        print('FS size            : %u' % fsSize)
        print('encrypted upto     : %u' % encrypted_upto)
        print('hash first block   : %s' % hash_first_block.hex().upper())
        print('keymaster blob     : %s...[%d]' % (km_blob.hex().upper()[0:32], km_blob_size))
        print('scrypted IK        : %s' % scrypted_intermediate_key.hex().upper())
        print("\n")
    print('| -------------------------')
    return cryptoKey, cryptoSalt


def decrypt_data(encryption_key, salt, passwd, data, debug=True):
    key_size = len(encryption_key)
    # print(key_size)
    assert (key_size == 16 or key_size == 32), "Oversize key"

    pbkdf2 = pbkdf2_hmac(PBKDF2_ALGO, passwd, salt, HASH_COUNT, keylen=key_size+IV_LEN_BYTES)
    key_hash = pbkdf2[:key_size]
    iv = pbkdf2[key_size:]
    # print(pbkdf2.hex().upper())
    cipher_for_key = AES.new(key_hash, AES.MODE_CBC, iv)
    key = cipher_for_key.decrypt(encryption_key)
    # key_sha256 = hashlib.sha256(key)
    # print(key_sha256.digest())
    if debug:
        print('Password       :', passwd)
        print('Derived Key    :', "0x" + key_hash.hex().upper())
        print('Derived IV     :', "0x" + iv.hex().upper())
        print('Decrypted Key  :', "0x" + key.hex().upper())
        print('----------------')

    salt = hashlib.sha256(key).digest()
    sector_number = struct.pack("<I", 2) + b'\x00' * (BLOCK_SIZE - 4)
    cipher = AES.new(key=salt, mode=AES.MODE_ECB)
    essiv = cipher.encrypt(sector_number)
    if debug:
        print('SECTOR NUMBER  :', "0x" + sector_number.hex().upper())
        print('ESSIV SALT     :', "0x" + salt.hex().upper())
        print('ESSIV IV       :', "0x" + essiv.hex().upper())
        print('----------------')
    # cipher_for_data = AES.new(cipher_for_sector, AES.MODE_CBC, iv)
    cipher_for_data = AES.new(key, AES.MODE_CBC, essiv)
    data = cipher_for_data.decrypt(data)
    return data


def bruteforce_data(data_file, key, salt):
    fd = open(data_file, 'rb')
    data = fd.read(1024)
    fd.close()
    print(data.hex())

    passwd = '1234'
    # print(len(key))
    dec_data = decrypt_data(key, salt, passwd, data)

    print(f'DATA BEFORE\t{data.hex()}')
    print(f'DATA AFTER\t{dec_data.hex()}')
    return


def main():
    parser = argparse.ArgumentParser(description='Decrypt FDE Android')
    parser.add_argument('en_part', help='Encrypted /data partition')
    parser.add_argument('footer', help='Footer struct')
    args = parser.parse_args()
    assert os.path.isfile(args.footer), f"Footer file {args.footer} is not found"
    assert os.path.isfile(args.en_part), f"Dump file {args.en_part} is not found"

    key, salt = parse_footer(args.footer)
    bruteforce_data(args.en_part, key, salt)
    return


if __name__ == "__main__":
    main()
