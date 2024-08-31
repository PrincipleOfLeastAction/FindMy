#!/usr/bin/env python3
import glob
import datetime
import base64,json
import hashlib
import codecs,struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import socket
import time

def bytes_to_int(b):
    return int(codecs.encode(b, 'hex'), 16)

def sha256(data):
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()

def decrypt(enc_data, algorithm_dkey, mode):
    decryptor = Cipher(algorithm_dkey, mode, default_backend()).decryptor()
    return decryptor.update(enc_data) + decryptor.finalize()

def decode_tag(data):
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    horizontal_accuracy = bytes_to_int(data[8:9])
    status = bytes_to_int(data[9:10])
    return {'lat': latitude, 'lon': longitude, 'horizontal accuracy': horizontal_accuracy, 'status':status}

def request_raw_data(ip, port, ids, start_unix_time, end_unix_time):
    unix_time_to_apple_time = lambda t: (t - 978307200) * 1000000
    start_apple_time = unix_time_to_apple_time(start_unix_time)
    end_apple_time = unix_time_to_apple_time(end_unix_time)
    
    data = '{"search": [{%s"ids": %s}]}' % (
        f'"startDate": {start_apple_time}, "endDate": {end_apple_time}, ', 
        list(ids.keys())
    )
    data = data.replace("'", '"')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(bytes(data + '\n', encoding='ascii'))
        response = b''
        while True:
            rdata = sock.recv(1024)
            if not rdata: break
            response += rdata

    res = json.loads(response)['results']
    return res

def open_key_files(key_file_prefix: str="") -> tuple[dict, dict]:
    ids = {}
    names = {}
    for keyfile in glob.glob(key_file_prefix + '*.keys'):
        # read key files generated with generate_keys.py
        with open(keyfile) as f:
            hashed_adv = ''
            priv = ''
            name = keyfile[len(key_file_prefix):-5]
            for line in f:
                key = line.rstrip('\n').split(': ')
                if key[0] == 'Private key':
                    priv = key[1]
                elif key[0] == 'Hashed adv key':
                    hashed_adv = key[1]

            if priv and hashed_adv:
                ids[hashed_adv] = priv
                names[hashed_adv] = name
            else:
                print("Couldn't find key pair in", keyfile)
    return ids, names

def decrypt_data(res, ids, names):
    ordered = []
    found = set()
    for report in res:
        priv = bytes_to_int(base64.b64decode(ids[report['id']]))
        data = base64.b64decode(report['payload'])

        # the following is mostly copied from https://github.com/hatomist/openhaystack-python, thanks @hatomist!
        # Changes include getting the confidence field from the data received as opposed to the
        # horizontal accuracy field
        timestamp = bytes_to_int(data[0:4])
        confidence = bytes_to_int(data[4:5])
        
        # Fixes issue with this not being decrypted correctly sometimes.
        # https://github.com/biemster/FindMy/issues/52
        if len(data) > 88:
            data = data[0:4] + data[5:]
        try:
            eph_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), data[5:62])
        except Exception as e:
            print(e)
            continue
        shared_key = ec.derive_private_key(priv, ec.SECP224R1(), default_backend()).exchange(ec.ECDH(), eph_key)
        symmetric_key = sha256(shared_key + b'\x00\x00\x00\x01' + data[5:62])
        decryption_key = symmetric_key[:16]
        iv = symmetric_key[16:]
        enc_data = data[62:72]
        tag = data[72:]

        decrypted = decrypt(enc_data, algorithms.AES(decryption_key), modes.GCM(iv, tag))
        res = decode_tag(decrypted)
        res['conf'] = confidence
        res['timestamp'] = timestamp + 978307200
        res['isodatetime'] = datetime.datetime.fromtimestamp(res['timestamp']).isoformat()
        res['key'] = names[report['id']]
        res['goog'] = 'https://maps.google.com/maps?q=' + str(res['lat']) + ',' + str(res['lon'])
        found.add(res['key'])
        ordered.append(res)
    ordered.sort(key=lambda item: item.get('timestamp'))
    
    return ordered, found
