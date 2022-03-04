#!/usr/bin/env python3

import socket
import sys
import selectors
import types
import json

from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.integer import randomBits,integer,bitsize
from charm.toolbox.hash_module import Hash,int2Bytes,integer
from charm.toolbox.IBEnc import IBEnc

HOST = "127.0.0.1"
PORT = 12345

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print(f"[+] Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def get_parameters(ID):
    ecc = ['MNT224', 1024]
    sk = ibe.extract(RA_priv_key, ID)
    sk = str(sk).replace('\'', '"')
    sk = json.loads(sk)
    # TODO: remove the private key of RA from the parameters
    return json.dumps({"sk":sk['id'], "P": str(RA_pub_key["P"]), "P2": str(RA_pub_key["P2"]), "s": str(RA_priv_key["s"]), "ecc": ecc[0], 'bits': ecc[1]})

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(2048)  # Should be ready to read
        if recv_data:
            data.outb += recv_data
        else:
            print(f"[!] Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            # extract data from the message
            resp = json.loads(str(data.outb)[2:-1])
            print(f'[+] {resp["Entity"]} requesting registration')
            ID = resp["ID"]

            # generate private key and send parameters for the cryptosystem
            params = get_parameters(ID)
            print('[*] Send parameters back!')
            sent = sock.send(bytes(params, encoding='utf-8'))  # Should be ready to write
            data.outb = data.outb[sent:]


''' 
RA Server and Crypto setup 
'''
print('----------- RA ------------')
sel = selectors.DefaultSelector()

# listening server
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((HOST, PORT))
lsock.listen()
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)
# crytpo part
group = PairingGroup('MNT224', secparam=1024)   # use of the same default curve of the example
ibe = IBE_BonehFranklin(group)  # initialization of the scheme
(RA_pub_key, RA_priv_key) = ibe.setup() # RA setup keys
print('[+] Initialization completed successfully!')
print(f"[+] Listening on {(HOST, PORT)}...")

# start listening 
try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)

except KeyboardInterrupt:
    print('\n[!] Caught keyboard interrupt, exiting!')

finally:
    sel.close()

