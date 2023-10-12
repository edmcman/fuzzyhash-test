#!/usr/bin/python

from pyLZJD import digest, sim

import sys
import json
import subprocess
import tqdm

j1 = json.load(open(sys.argv[1], "r"))
j2 = json.load(open(sys.argv[2], "r"))

# pyLZJD sim seems wrong
import numpy as np

# Keep sims in sorted order by distance and remove changed pairs
def greedy_entity_matching(sims):
    # we don't need the bytes anymore
    sims = [(a,b,e) for (a,b,c,d,e) in sims]
    matches = []  # List to store matched pairs

    setA = {t[0] for t in sims}
    setB = {t[1] for t in sims}

    for _ in tqdm.trange(min(len(setA),len(setB))):
        if not sims:
            return matches

        best_match = sims[0]
        sims = [x for x in sims[1:] if x[0] != best_match[0] and x[1] != best_match[1]]

        matches.append(best_match)

    return matches

def greedy_entity_matching_other(setA, setB, distance_metric):
    matches = []  # List to store matched pairs

    for _ in tqdm.trange(min(len(setA),len(setB))):
        if not (setA and setB):
            return matches

        best_match = None
        best_distance = float('inf')

        for entityA in setA:
            for entityB in setB:
                distance = distance_metric(entityA, entityB)

                if distance < best_distance:
                    best_distance = distance
                    best_match = (entityA, entityB)

        if best_match:
            matches.append(best_match)
            setA.remove(best_match[0])
            setB.remove(best_match[1])

    return matches

def eds_sim(A, B):
    if isinstance(A, tuple):
        A = A[0]
    if isinstance(B, tuple):
        B = B[0]
    
    #What type of hash did we use? If its a np.float32, we did SuperHash
    if A.dtype == np.float32:
        return np.sum(A == B)/A.shape[0]
    #Else, we are doing the normal case of set intersection
    
    #intersection_size = lzjd_cython.intersection_size(A, B)
    intersection_size = float(np.intersect1d(A, B, assume_unique=True).shape[0])
    
    #hashes should normally be the same size. Its possible to use different size hashesh tough. 
    #Could happen from small files, or just calling with differen hash_size values
    
    #What if the hashes are different sizes? Math works out that we can take the min length
    #Reduces as back to same size hashes, and its as if we only computed the min-hashing to
    #*just* as many hashes as there were members

    # double sim = same / (double) (x_minset.length + y_minset.length - same);

    return intersection_size / (A.shape[0] + B.shape[0] - intersection_size)

    #min_len = min(A.shape[0], B.shape[0])
    
    #return intersection_size/float(2*min_len - intersection_size)

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

funs1 = {fun['fn_addr']: (fun['pic_bytes'], digest(fun['pic_bytes'])) for fun in tqdm.tqdm(j1['analysis'])}
funs2 = {fun['fn_addr']: (fun['pic_bytes'], digest(fun['pic_bytes'])) for fun in tqdm.tqdm(j2['analysis'])}

from itertools import product

sims = [(fun1_addr, fun2_addr, fun1_bytes, fun2_bytes, eds_sim(fun1_hash, fun2_hash)) for (fun1_addr, (fun1_bytes, fun1_hash)), (fun2_addr, (fun2_bytes, fun2_hash)) in tqdm.tqdm(product(funs1.items(), funs2.items()), total=len(funs1)*len(funs2))]
sims.sort(key=lambda t: -t[4])
for f1, f2, b1, b2, sim in tqdm.tqdm(sims):
    print("%s,%s,%s,%s,%s" % (name_fun(f1, m1), name_fun(f2, m2), sim, b1, b2)) 

#A = set(funs1.keys())
#B = set(funs2.keys())

#dist = lambda f1, f2: -eds_sim(funs1[f1][1], funs2[f2][1])

intersect_fun_names = set(name_fun(f, m1) for f in funs1.keys()) & set(name_fun(f, m2) for f in funs2.keys())
#print(intersection_funs)

matches = greedy_entity_matching(sims)

# This is too big to write all of them
if False:
    for f1, f2, sim in matches:
        print("%s matches with %s (%s)" % (name_fun(f1, m1), name_fun(f2, m2), sim))

# How many (fun, fun, _) matches do we have?
correct_matches = [(fun if any(name_fun(f1, m1) == fun and name_fun(f2, m2) == fun for f1, f2, sim in matches) else None) for fun in intersect_fun_names]
correct_matches = [x for x in correct_matches if x is not None]
num_correct = len(correct_matches)
accuracy = num_correct / float(len(intersect_fun_names))

#print(correct_matches)
for fun in correct_matches:
    print("Correct match: %s" % (fun))

print(f"Accuracy: {accuracy}")