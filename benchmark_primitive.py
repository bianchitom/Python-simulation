#!/usr/bin/env python3

from statistics import mean
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR,G1,G2,pair
from charm.core.math.pairing import ZR,G1,GT,pair
from charm.toolbox.hash_module import Hash
from charm.toolbox.IBEnc import IBEnc
from charm.toolbox.hash_module import Waters
import numpy as np

group = PairingGroup('SS512', secparam=1024) # S512 is in symmetric pairing


times = 100000
trials = 1

g = group.random(G1)
h = group.random(G1)
i = group.random(G2)

rt = []
ct = []
for i in range(times):
    assert group.InitBenchmark(), "failed to initialize benchmark"
    group.StartBenchmark(["RealTime", "CpuTime", "Mul"])
    for a in range(trials):
        #j = g * h
        #k = i ** group.random(ZR)
        # t = (j ** group.random(ZR)) / h
        n = pair(g, h)
    group.EndBenchmark()

    msmtDict = group.GetGeneralBenchmarks()
    rt.append(msmtDict['RealTime'])
    ct.append(msmtDict['CpuTime'])
    #real_time = msmtDict['RealTime'] 
    #cpu_time = msmtDict['CpuTime'] 
    #mul = msmtDict['Mul'] // trials
    # exp = msmtDict['Exp'] // trials
    # pair = msmtDict['Pair'] // trials
    # print(f'[4] Exp: {exp}')
    # print(f'[5] Pair: {pair}')

print('========= General Results =========')
print("Results for a single pair operation: ") # divide by the number of iteration: it should be good even with the "cheat" for k_ev and k_cspa
print(f'[1] Real Time: mean = {np.mean(rt)}, max = {np.max(rt)}, min = {np.min(rt)}')
print(f'[2] Cpu Time: mean = {np.mean(ct)}, max = {np.max(ct)}, min = {np.min(ct)}')