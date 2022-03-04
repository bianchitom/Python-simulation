#!/usr/bin/env python3

import json
import uuid

from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.integer import randomBits,integer,bitsize
from charm.toolbox.hash_module import Hash,int2Bytes,integer
from charm.toolbox.IBEnc import IBEnc


group = PairingGroup('MNT224', secparam=1024)   # use of the same default curve of the example
ibe = IBE_BonehFranklin(group)  # initialization of the scheme
(RA_pub_key, RA_priv_key) = ibe.setup() # RA setup keys


ID = str(uuid.uuid4().hex)
sk = ibe.extract(RA_priv_key, ID)

print(type(sk['id']))
print(sk['id'])
print(type(sk))
print(sk)
sk = str(sk).replace('\'', '"')
sk = json.loads(sk)


ecc = ['MNT224', 1024]
test = json.dumps({"sk":sk['id'], "ecc": ecc[0], 'bits': ecc[1]})
#print(test)