#!/usr/bin/env python3

from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.pairing import ZR,G1,GT,pair
from charm.toolbox.hash_module import Hash
from charm.toolbox.IBEnc import IBEnc
from charm.toolbox.hash_module import Waters

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

trials = 1

group = PairingGroup('SS512', secparam=1024) # S512 is in symmetric pairing

# benchamrk for the authentication phase
assert group.InitBenchmark(), "failed to initialize benchmark"
group.StartBenchmark(["Mul", "Exp", "Pair"])

for _ in range(1, trials+1):

    group.EndBenchmark()

msmtDict = group.GetGeneralBenchmarks()
mul = msmtDict['Mul'] // trials
exp = msmtDict['Exp'] // trials
pair = msmtDict['Pair'] // trials
print('========= General Results =========')
print("Results for a single iteration: ") # divide by the number of iteration: it should be good even with the "cheat" for k_ev and k_cspa
print(f'[3] Mul: {mul}')
print(f'[4] Exp: {exp}')
print(f'[5] Pair: {pair}')