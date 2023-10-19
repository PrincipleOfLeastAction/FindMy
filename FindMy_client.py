#!/usr/bin/env python3
import glob
import datetime
import argparse
import base64,json
import hashlib
import codecs,struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import socket
import time
import sqlite3

def open_table():
    create_location_table_query = """
        CREATE TABLE IF NOT EXISTS location (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key TEXT,
          lat REAL NOT NULL,
          lon REAL NOT NULL,
          horizontal_accuracy INTEGER,
          status INTEGER,
          conf INTEGER,
          timestamp INTEGER,
          UNIQUE(key, lat, lon, horizontal_accuracy, status, conf, timestamp) ON CONFLICT IGNORE
        );
        """
        
    sqliteConnection = sqlite3.connect("airtag_location.db")
    cursor = sqliteConnection.cursor()
    
    cursor.execute(create_location_table_query)
    sqliteConnection.commit()
    return sqliteConnection, cursor
    
def insert_data(connection, cursor, data):
    for d in data:
        query = f"""
        INSERT OR IGNORE INTO
          location (key, lat, lon, horizontal_accuracy, status, conf, timestamp)
        VALUES
          ('{d['key']}', {d['lat']}, {d['lon']}, {d['horizontal accuracy']}, {d['status']}, {d['conf']}, {d['timestamp']});
        """ 
        cursor.execute(query)
    connection.commit()

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--prefix', help='only use keyfiles starting with this prefix', default='')
    parser.add_argument('-m', '--map', help='show map using OSM', default=False, action='store_true')
    args = parser.parse_args()

    ids = {}
    names = {}
    for keyfile in glob.glob(args.prefix+'*.keys'):
        # read key files generated with generate_keys.py
        with open(keyfile) as f:
            hashed_adv = ''
            priv = ''
            name = keyfile[len(args.prefix):-5]
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
    
    unixTime = int(time.time())
    endTime = (unixTime - 978307200) * 1000000
    startTime = (unixTime - 60 * 60 * 24 - 978307200) * 1000000
    data = '{"search": [{%s"ids": %s}]}' % ('' if args.map else 
        f'"endDate": {endTime}, "startDate": {startTime}, ', 
        list(ids.keys())
    )
    data = data.replace("'", '"')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('', 6176))
        sock.sendall(bytes(data + '\n', encoding='ascii'))
        response = b''
        while True:
            rdata = sock.recv(1024)
            if not rdata: break
            response += rdata
    finally:
        sock.close()
    res = json.loads(response)['results']
    print('%d reports received.' % len(res))

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
        eph_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), data[5:62])
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

    if args.map:
        import folium,webbrowser
        iconcolors = ['red','blue','green','purple','pink','orange','beige','darkred','darkblue','darkgreen','darkpurple','lightred','lightblue','lightgreen','cadetblue','gray','lightgray','black']
        osmap = folium.Map((ordered[-1]['lat'],ordered[-1]['lon']), zoom_start=15)
        for rep in ordered:
            dt = rep["isodatetime"].split('T')
            popup = folium.Popup(folium.IFrame(html=f'<h1>{rep["key"]}</h1> <h3>{dt[0]}</h3> <h3>{dt[1]}</h3>', width=150, height=150))
            osmap.add_child(folium.Marker(location=(rep['lat'],rep['lon']), popup=popup, icon=folium.Icon(color=iconcolors[list(found).index(rep['key'])])))
        osmap.save('/tmp/tags.html')
        webbrowser.open('file:///tmp/tags.html')
    else:
        for rep in ordered: print(rep)

    # Now save the data to the database.
    conn, cursor = open_table()
    insert_data(conn, cursor, ordered)
    conn.close()

    print('found:   ', list(found))
    print('missing: ', [key for key in names.values() if key not in found])
