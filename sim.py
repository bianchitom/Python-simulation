#!/usr/bin/env python3

'''
Boneh-Franklin Identity Based Encryption
  
| From: "D. Boneh, M. Franklin Identity-Based Encryption from the Weil Pairing", Section 4.2.
| Published in: Crypto 2003
| Available from: http://.../bfibe.pdf
| Notes: This is the IBE .
* type:           encryption (identity-based)
* setting:        bilinear groups (asymmetric)
:Authors:    J. Ayo Akinyele
:Date:       2/2011
'''

'''
TODO: unique file for simulate all the protocol and benchmark
'''

from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.integer import randomBits,integer,bitsize
from charm.core.math.pairing import pairing,pc_element,ZR,G1,G2,GT,init,pair,hashPair,H,random,ismember,order
from charm.toolbox.hash_module import Hash,int2Bytes,integer
from charm.toolbox.IBEnc import IBEnc

import uuid
import json

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# example of encryption/decryption
ID_ra = str(uuid.uuid4().hex)
group = PairingGroup('SS512', secparam=1024) # use of the same default curve of the example, SS512 is in symmetric pairing?
ibe = IBE_BonehFranklin(group) # initialization of the scheme
h = Hash(group)
(RA_pub_key, RA_priv_key) = ibe.setup() # RA setup
print(f'{bcolors.OKGREEN}[+] RA generates the parameters of the system{bcolors.ENDC}')

# CSPA registration
ID_cspa = str(uuid.uuid4().hex)
cspa_priv_key = ibe.extract(RA_priv_key, ID_cspa)
print(f'[+] CSPA registered to RA with ID {ID_cspa}')

# EV registration
ID_ev = str(uuid.uuid4().hex)
PID_ev = str(uuid.uuid4().hex)
ev_priv_key = ibe.extract(RA_priv_key, ID_ev)
pid_priv_key = ibe.extract(RA_priv_key, PID_ev)
print(f'[+] EV registered to RA with ID {ID_ev} and PID {PID_ev}')

# EV-CSPA Authentication phase
print(f'[+] EV generaters nonce and random to send to CSPA')
nonce_ev = group.random(ZR)
random_ev = group.random(ZR)
p_ev = random_ev*RA_pub_key['P']
print(f'{bcolors.OKBLUE}[1] EV sends m1 to CSPA (nonce_ev, r_ev*P){bcolors.ENDC}')

print(f'{bcolors.WARNING}[*] CSPA receives the message from EV for starting the authentication process{bcolors.ENDC}')
nonce_cspa = group.random(ZR)
random_cspa = group.random(ZR)
p_cspa = random_cspa*RA_pub_key['P']
print(f'{bcolors.OKBLUE}[2] CSPA sends m2 to EV (nonce_cspa, r_cspa*P, ID_cspa){bcolors.ENDC}')

# EV computes the keys and mac for the session with PID
print(f'{bcolors.WARNING}[*] EV computes the key pair for the bilinear mapping{bcolors.ENDC}')
k_ev = pair(group.hash(ID_cspa, G1), group.hash([pid_priv_key, h.hashToZr(ID_ra + PID_ev)], G1))
k_ev2 = random_ev*p_cspa
#print(k_ev)

m3 = bytes(json.dumps({"ID_ra": ID_ra, "PID": PID_ev}), encoding='utf-8')
cipher = ibe.encrypt(RA_pub_key, ID_cspa, m3)
print(f'{bcolors.OKBLUE}[3] EV sends m3 to CSPA (ID_ra, PID) encrypted with ID cspa{bcolors.ENDC}')

# CSPA receives the encrypted message and decrypt it
m3_dec = json.loads(ibe.decrypt(RA_pub_key, cspa_priv_key, cipher))

# CSPA computes its own parameters
print(f'{bcolors.WARNING}[*] CSPA computes the key pair for the bilinear mapping{bcolors.ENDC}')
# k_cspa = pair(cspa_priv_key, group.hash([group.hash(ID_ra, G1), h.hashToZr(ID_ra + PID_ev)], G1))
k_cspa2 = random_cspa*p_ev
# print(k_cspa)

assert k_ev2 == k_cspa2, f'{bcolors.OKCYAN}[!] k2 are DIFFERENT!{bcolors.ENDC}'

# CSPA sends to EV the mac_cspa computed for amutual authentication
m4 = bytes(json.dumps({"mac_cspa": ID_ra}), encoding='utf-8')
cipher = ibe.encrypt(RA_pub_key, PID_ev, m4)
print(f'{bcolors.OKBLUE}[4] EV sends m4 to CSPA (ID_ra, PID) encrypted with ID cspa{bcolors.ENDC}')
m4_dec = json.loads(ibe.decrypt(RA_pub_key, pid_priv_key, cipher))
print(m4_dec)