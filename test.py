#!/usr/bin/env python3

from hashlib import sha256
import json
import uuid

from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup, ismember
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.integer import randomBits,integer,bitsize
from charm.toolbox.hash_module import Hash,int2Bytes,integer
from charm.toolbox.IBEnc import IBEnc


# example of encryption/decryption
ID_ra = str(uuid.uuid4().hex)
group = PairingGroup('SS512', secparam=1024) # use of the same default curve of the example, SS512 is in symmetric pairing?
ibe = IBE_BonehFranklin(group) # initialization of the scheme
h = Hash(group)
(RA_pub_key, RA_priv_key) = ibe.setup() # RA setup

# CSPA registration
ID_cspa = str(uuid.uuid4().hex)
cspa_priv_key = ibe.extract(RA_priv_key, ID_cspa)

# EV registration
ID_ev = str(uuid.uuid4().hex)
PID_ev = str(uuid.uuid4().hex)
ev_priv_key = ibe.extract(RA_priv_key, ID_ev)
pid_priv_key = ibe.extract(RA_priv_key, PID_ev)

# EV-CSPA Authentication phase
nonce_ev = group.random(ZR)
random_ev = group.random(ZR)
p_ev = random_ev*RA_pub_key['P']

nonce_cspa = group.random(ZR)
random_cspa = group.random(ZR)
p_cspa = random_cspa*RA_pub_key['P']

# EV computes the keys and mac for the session with PID
k_ev = group.pair_prod(group.hash(ID_cspa, G1), group.hash([ibe.extract(RA_priv_key, ID_ra), h.hashToZr(ID_ra + PID_ev)], G1))
k_ev2 = random_ev*p_cspa

# mac : it is encrypted with a hash functin and stop? 
print(f'k_ev {k_ev}')

# CSPA computes its own parameters
k_cspa = group.pair_prod(cspa_priv_key['id'], group.hash([group.hash(ID_ra, G1), h.hashToZr(ID_ra + PID_ev)], G1))
k_cspa2 = random_cspa*p_ev

print(f'k_cspa {k_cspa}')


print(k_ev == k_cspa)
