#!/usr/bin/python

from pyLZJD import digest, sim

import sys
import json
import subprocess

j1 = json.load(open(sys.argv[1], "r"))
j2 = json.load(open(sys.argv[2], "r"))

# get names from debug symbols
def symbol_map(bname):
    output = subprocess.check_output(f"nm -a {bname}", shell=True)
    splitz = [l.split(b" ") for l in output.splitlines()]
    return {int(t[0], 16): t[2] for t in splitz if t[0] != b""}

m1 = symbol_map(sys.argv[3])
m2 = symbol_map(sys.argv[4])

def name_fun(addrstr, m):
    addr = int(addrstr, 16)
    return m.get(addr, addrstr)

import pprint
pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(j)

funs1 = {fun['fn_addr']: digest(fun['exact_bytes']) for fun in j1['analysis']}
funs2 = {fun['fn_addr']: digest(fun['exact_bytes']) for fun in j2['analysis']}
#pp.pprint(funs)

from itertools import product

sims = [(fun1_addr, fun2_addr, sim(fun1_hash, fun2_hash)) for (fun1_addr, fun1_hash), (fun2_addr, fun2_hash) in product(funs1.items(), funs2.items())]
sims.sort(key=lambda t: t[2])
for f1, f2, sim in sims:
    print("%s,%s,%s" % (name_fun(f1, m1), name_fun(f2, m2), sim)) 
