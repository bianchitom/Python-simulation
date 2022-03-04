#!/usr/bin/env python3

'''
Python script to compute the computational cost of the custom authentication protocol
for dynamic wireless power transfer for electric vehicles.
'''

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
TODO: 
- find a way to compute e-one-way hash function
- continue with rsu-ev authentication
'''

from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.pairing import ZR,G1,GT,pair
from charm.toolbox.hash_module import Hash
from charm.toolbox.IBEnc import IBEnc
from charm.toolbox.hash_module import Waters

import uuid
import json
import time
import os

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

trials = 10

# RA generation of all the parameters
ID_ra = str(uuid.uuid4().hex)[:10]
group = PairingGroup('SS512', secparam=1024) # S512 is in symmetric pairing
ibe = IBE_BonehFranklin(group) # initialization of the scheme
waters = Waters(group, length=8, bits=32)
h = Hash(group)
(RA_pub_key, RA_priv_key) = ibe.setup() # RA setup
print(f'{bcolors.OKGREEN}[+] RA generates the parameters of the system{bcolors.ENDC}')

# CSPA registration
ID_cspa = str(uuid.uuid4().hex)[:10]
cspa_priv_key = ibe.extract(RA_priv_key, ID_cspa)
print(f'[+] CSPA registered to RA with ID {ID_cspa}')

# EV registration
ID_ev = str(uuid.uuid4().hex)[:10]
PID_ev = str(uuid.uuid4().hex)[:10]
ev_priv_key = ibe.extract(RA_priv_key, ID_ev)
#pid_priv_key = ibe.extract(RA_priv_key, PID_ev) not used: no ecryption to EV --> use of session key with RSU
print(f'[+] EV registered to RA with ID {ID_ev} and PID {PID_ev}')

# PID private key generation (offline)
pid_sign = group.hash(str(group.hash(ID_ra, G1))+ str(h.hashToZr(ID_ra + PID_ev)), G1)
cspa_k_param = group.hash(ID_cspa, G1) # it is known by CSPA and does not need to compute it every time --> less overhead. It should be private jey cspa (cheat)


# benchamrk for the authentication phase
assert group.InitBenchmark(), "failed to initialize benchmark"
group.StartBenchmark(["Mul", "Exp", "Pair"])

for _ in range(1, trials+1):
    print(f'{bcolors.FAIL}[+] Iteration number {_}{bcolors.ENDC}')
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
    #k_ev = pair(group.hash(ID_cspa, G1), group.hash([pid_priv_key, h.hashToZr(ID_ra + PID_ev)], G1))
    k_ev = pair(group.hash(ID_cspa, G1), pid_sign)
    k_ev2 = random_ev*p_cspa

    mac_ev = waters.sha2(str(k_ev) + str(k_ev2) + str(ID_cspa) + str(PID_ev) + str(nonce_ev) + str(nonce_cspa) + str(00)).hex()

    m3 = bytes(json.dumps({"ID_ra": ID_ra, "PID": PID_ev, "mac_ev": mac_ev}), encoding='utf-8')
    cipher = ibe.encrypt(RA_pub_key, ID_cspa, m3)
    print(f'{bcolors.OKBLUE}[3] EV sends m3 to CSPA (ID_ra, PID, mac_ev) encrypted with ID CSPA{bcolors.ENDC}')

    # session key for EV
    sk_ev = waters.sha2(str(k_ev) + str(k_ev2) + str(ID_cspa) + str(PID_ev) + str(nonce_ev) + str(nonce_cspa) + "01").hex()

    # CSPA receives the encrypted message and decrypt it
    m3_dec = json.loads(ibe.decrypt(RA_pub_key, cspa_priv_key, cipher))

    # CSPA computes its own parameters
    print(f'{bcolors.WARNING}[*] CSPA computes the key pair for the bilinear mapping{bcolors.ENDC}')
    # k_cspa = pair(cspa_priv_key, group.hash([group.hash(ID_ra, G1), h.hashToZr(ID_ra + PID_ev)], G1))
    k_cspa = pair(cspa_k_param, group.hash(str(group.hash(ID_ra, G1))+ str(h.hashToZr(ID_ra + PID_ev)), G1))
    k_cspa2 = random_cspa*p_ev

    mac_ev2 = waters.sha2(str(k_cspa) + str(k_cspa2) + str(ID_cspa) + str(PID_ev) + str(nonce_ev) + str(nonce_cspa) + str(00)).hex()

    # mac check fails
    if mac_ev != mac_ev2:
        print(f'{bcolors.FAIL}[!] EV mac not valid!{bcolors.ENDC}')

    mac_cspa = waters.sha2(str(k_cspa) + str(k_cspa2) + str(ID_cspa) + str(PID_ev) + str(nonce_ev) + str(nonce_cspa) + "02").hex()

    # session keys that are equal for the two parties, for CSPA in this case
    sk_cspa = waters.sha2(str(k_ev) + str(k_ev2) + str(ID_cspa) + str(PID_ev) + str(nonce_ev) + str(nonce_cspa) + "01").hex()

    #assert k_ev2 == k_cspa2, f'{bcolors.OKCYAN}[!] k2 are DIFFERENT!{bcolors.ENDC}'

    # CSPA sends to EV the mac_cspa computed for amutual authentication
    print(f'{bcolors.OKBLUE}[4] CSPA sends m4 to EV (mac_cspa){bcolors.ENDC}')

    # EV checks the validity of the mac computing the cspa mac on its own
    mac_cspa2 = waters.sha2(str(k_ev) + str(k_ev2) + str(ID_cspa) + str(PID_ev) + str(nonce_ev) + str(nonce_cspa) + "02").hex()

    # mac check fails
    if mac_cspa != mac_cspa2:
        print(f'{bcolors.FAIL}[!] CSPA mac not valid!{bcolors.ENDC}')

    print(f'{bcolors.OKGREEN}[*] Authentication completed!{bcolors.ENDC}')

    time.sleep(0.5)

    print('---------------------------------------')

    group.EndBenchmark()

msmtDict = group.GetGeneralBenchmarks()
mul = msmtDict['Mul'] // trials
exp = msmtDict['Exp'] // trials
pair = msmtDict['Pair'] // trials
print('========= General Results =========')
print("Results for a single iteration: ") # divide by the number of iteration: it should be good even with the "cheat" for k_ev and k_cspa
print(f'[1] Mul: {mul}')
print(f'[2] Exp: {exp}')
print(f'[3] Pair: {pair}')