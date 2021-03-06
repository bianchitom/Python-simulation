#!/usr/bin/env python3

import socket
import json
import uuid
import secrets 

from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup, init
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.integer import randomBits,integer,bitsize
from charm.toolbox.hash_module import Hash,int2Bytes,integer
from charm.toolbox.IBEnc import IBEnc

HOST = "127.0.0.1"
PORT_RA = 12345
PORT_CSPA = 23456

def request_RA(m):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_RA))
        print(f'[+] Requesting registration to RA')
        s.sendall(bytes(m, encoding='utf-8'))
        params = json.loads(str(s.recv(2048))[2:-1])

    return params

def get_public_key(P, P2, group):
    P = P.replace('[', '').replace(']', '').split(',')
    P = list(map(int, P))
    P2 = P2.replace('[', '').replace(']', '').split(',')
    P2 = list(map(int, P2))

    P = [P[:3], P[3:]] 
    P2 = [P2[:3], P2[3:]]

    P = group.init(ZR, P)
    P2 = group.init(ZR, P2)

    return {'P': P, 'P2': P2}

def get_private_key(sk, ID, s, group):  # TODO: remove the private key of RA
    d_ID = s * group.hash(ID, G1)   # TODO: modify here in order to covnert int to pairing.Element
    return  {'id': d_ID, 'IDstr': ID}

# generation ID and PID EV
ID_cspa = str(uuid.uuid4().hex)

m = json.dumps({"Entity": "CSPA", "ID": ID_cspa})

''' 
registration with RA for CSPA
'''
params = request_RA(m)
print("[*] Registration succesfull")
# build the cryptosystem
group = PairingGroup(str(params["ecc"]), secparam=int(params["bits"]))
ibe = IBE_BonehFranklin(group)
s = group.init(ZR, int(params["s"])) # TODO: private key or RA, private key EV not workin init method, returns always 0
mpk = get_public_key(params['P'], params['P2'], group)    # master public key

# get the private key
sk_CSPA = get_private_key(params['sk'], ID_cspa, s, group)


# CSPA starts a server waiting for EV to communicate
print(f'[+] Starting server for EV conncetion')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT_CSPA))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        data = json.loads(str(conn.recv(1024))[2:-1])
        if data["Entity"] == "EV":
            print(f'[+] EV wants to authenticate!')
        nonce_ev = data["N_ev"]
        random_ev = data["r_ev"]

        nonce_cspa = secrets.token_hex(8)
        random_cspa = secrets.token_hex(8)
        
        conn.send(bytes(json.dumps({"Entity": "CSPA", "N_ev": nonce_ev, "r_ev": random_ev, "ID": ID_cspa}), encoding='utf-8'))



''' 
CSPA-EV Authentication 
'''