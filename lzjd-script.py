#!/usr/bin/python

from pyLZJD import digest, sim
# pip install git+git://github.com/EdwardRaff/pyLZJD#egg=pyLZJD

import sys
import json

j1 = json.load(open(sys.argv[1], "r"))
j2 = json.load(open(sys.argv[2], "r"))

import pprint
pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(j)

funs1 = {fun['fn_addr']: digest(fun['exact_bytes']) for fun in j1['analysis']}
funs2 = {fun['fn_addr']: digest(fun['exact_bytes']) for fun in j2['analysis']}
#pp.pprint(funs)

from itertools import product
#for (fun1_addr, fun1_hash), (fun2_addr, fun2_hash) in product(funs1.items(), funs2.items()):
#    similarity = sim(fun1_hash, fun2_hash)
#    print("%s,%s,%s" % (fun1_addr, fun2_addr, similarity))

sims = [(fun1_addr, fun2_addr, sim(fun1_hash, fun2_hash)) for (fun1_addr, fun1_hash), (fun2_addr, fun2_hash) in product(funs1.items(), funs2.items())]
sims.sort(key=lambda t: t[2])
for f1, f2, sim in sims:
    print("%s,%s,%s" % (f1, f2, sim)) 
