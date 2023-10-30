#!/usr/bin/python

from pyLZJD import digest, sim

import math
import random
import sys
import json
import subprocess
import tqdm
import editdistance
import itertools

import sklearn.metrics

import collections

j1 = json.load(open(sys.argv[1], "r"))
j2 = json.load(open(sys.argv[2], "r"))

# pyLZJD sim seems wrong
import numpy as np

def lev_sim(a, b):
    maxlen = max(len(a), len(b))
    # When Ed doesn't want to wait for Lev distance...
    if True:
        d = editdistance.eval(a,b)
    else:
        d = 0.0
    #d = edit_distance(a, b, max_ed=maxlen)

    return 1.0 - (float(d) / maxlen)

# Keep sims in sorted order by distance and remove changed pairs
def greedy_entity_matching(sims):
    matches = []  # List to store matched pairs

    setA = {t[0] for t in sims}
    setB = {t[1] for t in sims}

    for _ in tqdm.trange(min(len(setA),len(setB)), desc="greedy alignment"):
        if not sims:
            return matches

        best_match = sims[0]
        sims = [x for x in sims[1:] if x[0] != best_match[0] and x[1] != best_match[1]]

        matches.append(best_match)

    return matches

def greedy_entity_matching_other(setA, setB, distance_metric):
    matches = []  # List to store matched pairs

    for _ in tqdm.trange(min(len(setA),len(setB)), desc="other greedy alignment"):
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
    union_size = float(np.union1d(A, B).shape[0])
    
    #hashes should normally be the same size. Its possible to use different size hashesh tough. 
    #Could happen from small files, or just calling with differen hash_size values
    
    #What if the hashes are different sizes? Math works out that we can take the min length
    #Reduces as back to same size hashes, and its as if we only computed the min-hashing to
    #*just* as many hashes as there were members

    # double sim = same / (double) (x_minset.length + y_minset.length - same);

    return intersection_size / union_size

    #min_len = min(A.shape[0], B.shape[0])
    
    #return intersection_size/float(2*min_len - intersection_size)

# get names from debug symbols
def symbol_map(bname):
    output = subprocess.check_output(f"nm -l {bname}", shell=True)
    splitz = [l.split(b" ") for l in output.splitlines()]
    # nm -l seems to identify real functions pretty well; they have \t in them

    # We get a string like "asdfasdfsaf\tfile.cpp:1234".  This doesn't work for
    # exp4. So for now we'll just use the name.
    tmpd = {int(t[0], 16): t[2].split(b"\t")[0] for t in splitz if t[0] != b"" and b"\t" in t[2]}

    # Look for duplicate names
    counter1 = collections.Counter(tmpd.values())
    for item, cnt in counter1.items():
        if cnt > 1:
            print(f"Ignoring duplicate {item}")

    # Look for duplicate addresses
    # Remove dups
    return {k: v for k, v in tmpd.items() if counter1[v] == 1}
    

m1 = symbol_map(sys.argv[3])
m2 = symbol_map(sys.argv[4])

def name_fun(addrstr, m, return_none_for_unknown=False):
    addr = int(addrstr, 16)
    return m.get(addr, None if return_none_for_unknown else addrstr)

funs1 = {fun['fn_addr']: (fun['pic_bytes'], digest(fun['pic_bytes'])) for fun in tqdm.tqdm(j1['analysis'], desc="hashing functions")}
funs2 = {fun['fn_addr']: (fun['pic_bytes'], digest(fun['pic_bytes'])) for fun in tqdm.tqdm(j2['analysis'], desc="hashing functions")}

# Only compare functions for which we have names...
funs1 = {k: v for k,v in funs1.items() if name_fun(k, m1, return_none_for_unknown=True) is not None}
funs2 = {k: v for k,v in funs2.items() if name_fun(k, m2, return_none_for_unknown=True) is not None}

#sims = [(fun1_addr, fun2_addr, fun1_bytes, fun2_bytes, eds_sim(fun1_hash, fun2_hash)) for (fun1_addr, (fun1_bytes, fun1_hash)), (fun2_addr, (fun2_bytes, fun2_hash)) in tqdm.tqdm(itertools.product(funs1.items(), funs2.items()), total=len(funs1)*len(funs2), desc="Comparing all pairs")]
#random.shuffle(sims)
#sims.sort(key=lambda t: -t[4])

# We can't write all pairs for openssl, it's too big.
if False:
    for f1, f2, b1, b2, sim in tqdm.tqdm(sims):
        print("%s,%s,%s,%s,%s" % (name_fun(f1, m1), name_fun(f2, m2), sim, b1, b2)) 

#A = set(funs1.keys())
#B = set(funs2.keys())

#dist = lambda f1, f2: -eds_sim(funs1[f1][1], funs2[f2][1])

fun_names1 = set(name_fun(f, m1, return_none_for_unknown=True) for f in funs1.keys())
fun_names2 = set(name_fun(f, m2, return_none_for_unknown=True) for f in funs2.keys())
intersect_fun_names = fun_names1 & fun_names2
all_fun_names = fun_names1 | fun_names2
#print(intersection_funs)

print(f"All fun names: {all_fun_names}")
print(f"Intersection of names: {intersect_fun_names}")
print(f"Functions in one but not both {all_fun_names - intersect_fun_names}")

if False:
    matches = greedy_entity_matching(sims)
    for f1, f2, b1, b2, sim in tqdm.tqdm(matches, desc="Printing matches"):
        name1 = name_fun(f1, m1)
        name2 = name_fun(f2, m2)
        lev = lev_sim(b1, b2)
        print("%s <==> %s (sim=%s; lev=%s)" % (name1, name2, sim, lev))
        correct = name1 == name2 and name1 in intersect_fun_names and name2 in intersect_fun_names
        print("PLOTLZJD,%s,%s,%s,%s,%s" % (correct, name1, name2, sim, lev))

    # How many (fun, fun, _) matches do we have?
    correct_matches = [next(((fun, sim) for f1, f2, _, _, sim in matches if name_fun(f1, m1) == fun and name_fun(f2, m2) == fun), None) for fun in intersect_fun_names]
    correct_matches = dict(x for x in correct_matches if x is not None)
    num_correct = len(correct_matches)
    accuracy = num_correct / float(len(intersect_fun_names))

    #print(correct_matches)

    for fun in intersect_fun_names:
        if fun in correct_matches:
            sim = correct_matches[fun]
            print(f"Correct LZJD match: {fun} (sim={sim})")
        else:
            print(f"Incorrect LZJD match: {fun}")

    # Since we have the fn2hash json parsed and everything here, it makes sense to
    # just compute the TP and FP for PIC hash here.

    # But there can be multiple functions with the same PIC hash in a binary.  So,
    # what we'll do is use the greedy matching algorithm, which will pick an
    # arbitrary match if there are multiple functions with the same PIC hash.

    #j1hash = {f['fn_addr']: f['pic_hash'] for f in j1['analysis']}
    #j2hash = {f['fn_addr']: f['pic_hash'] for f in j2['analysis']}

    pic_comparisons = [(addr1, addr2, 1.0 if hash1 == hash2 else 0.0) for ((addr1, (hash1, _)), (addr2, (hash2, _))) in itertools.product(funs1.items(), funs2.items())]
    random.shuffle(pic_comparisons)
    pic_comparisons.sort(key=lambda t: -t[2])

    pic_matches = greedy_entity_matching(pic_comparisons)

    for f1, f2, sim in pic_matches:
        name1 = name_fun(f1, m1)
        name2 = name_fun(f2, m2)
        correct = name1 == name2 and name1 in intersect_fun_names and name2 in intersect_fun_names
        lev = lev_sim(b1, b2)
        print("PLOTFSE,%s,%s,%s,%s,%s" % (correct, name1, name2, sim, lev))

def cmp(addr1, addr2, pred):
    return (pred, (name_fun(addr1, m1) == name_fun(addr2, m2)))

# Compare each pair a single time
# addr1, addr2, bytes eq, fuzzy hash sim, lev sim, ground truth eq
all_comparisons = [(addr1, addr2, bytes1 == bytes2, eds_sim(fuzzyhash1, fuzzyhash2), lev_sim(bytes1, bytes2), name_fun(addr1, m1) == name_fun(addr2, m2)) for ((addr1, (bytes1, fuzzyhash1)), (addr2, (bytes2, fuzzyhash2))) in tqdm.tqdm(itertools.product(funs1.items(), funs2.items()), desc="all comparisons loop", total=len(funs1)*len(funs2))]

# fse
y_fse = [(eq, groundeq) for (_, _, eq, _, _, groundeq) in tqdm.tqdm(all_comparisons, desc="inner fse")]

#print(list(y))

y_predfse, y_true = zip(*y_fse)

def summarize_confusion(m):
    tp = m[0][0]
    fn = m[0][1]
    fp = m[1][0]
    tn = m[1][1]
    positive = sum(m[0])
    negative = sum(m[1])
    pp = m[0][0] + m[1][0]
    accuracy = (m[0][0] + m[1][1]) / (positive + negative)
    try:
        recall = tp / positive
    except:
        recall = None
    try:
        precision = tp / pp
    except:
        precision = None

    if recall is None or math.isnan(recall):
        recall = 1e-6
    if precision is None or math.isnan(precision):
        precision = 1e-6

    return {"accuracy": accuracy, "recall": recall, "precision": precision, "f1": 2 * (recall * precision) / (recall + precision)}

fsecm = sklearn.metrics.confusion_matrix(y_true, y_predfse, labels=[True, False])
fsesum = summarize_confusion(fsecm)
fsesum.update({"technique": "pic"})
print(f"FSE\n{fsecm}\n{fsesum}")

threshold_range = list(np.arange(0.0,1.01,0.05))


# lzjd
lzjds = []
for t in tqdm.tqdm(threshold_range, desc="lzjd iterations"):

    y_lzjd = [(sim >= t, eq) for (_, _, _, sim, _, eq) in tqdm.tqdm(all_comparisons, desc="inner tqdm")]

    y_predlzjd, _ = zip(*y_lzjd)

    cm = sklearn.metrics.confusion_matrix(y_true, y_predlzjd, labels=[True, False])
    levsum = summarize_confusion(cm)
    levsum.update({"threshold": t, "technique": "lzjd"})
    lzjds = lzjds + [levsum]
    print(f"LZJD {t}\n{cm}\n{levsum}")

# edit distance
# XXX refactor me to avoid duplicating edit distance computations
levs = []
for t in tqdm.tqdm(threshold_range, desc="ed iterations"):

    y_lev = [(sim >= t, eq) for (_, _, _,_, sim, eq) in tqdm.tqdm(all_comparisons, desc="inner lev")]

    y_predlev, _ = zip(*y_lev)

    cm = sklearn.metrics.confusion_matrix(y_true, y_predlev, labels=[True, False])
    levsum = summarize_confusion(cm)
    levsum.update({"threshold": t, "technique": "lev"})
    levs = levs + [levsum]
    print(f"LEV {t}\n{cm}\n{levsum}")


# thanks chatgpt!
import matplotlib.pyplot as plt
import matplotlib.cm as cm

data = lzjds + levs + [fsesum]

print(data)

def get_best_threshold(technique):
    return max((d for d in data if d['technique'] == technique), key=lambda row: row['f1'])

techniques = {}
for entry in data:
    technique = entry['technique']
    if technique not in techniques:
        techniques[technique] = {'precision': [], 'recall': [], 'threshold': []}
    techniques[technique]['precision'].append(entry['precision'])
    techniques[technique]['recall'].append(entry['recall'])
    if 'threshold' in entry:
        techniques[technique]['threshold'].append(entry['threshold'])

# Create a color map for different techniques
colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k']
markers = ['o', 's', '^', 'v', '<', '>', 'p', '*', 'H', '+', 'x', 'D']
linestyles = ['-', '--', '-.', ':', '-', '--', '-.', ':'] 

# Use a colormap, e.g., 'viridis'
colormap = cm.viridis
# Create a normalization based on these values
norm = plt.Normalize(0.0, 1.0)

THRESHOLD = (0.05, 0.02)

# Create the plot
for i, technique in enumerate(techniques):
    # Sort the data by threshold for correct sequencing of colors
    sorted_indices = np.argsort(techniques[technique]['threshold'])
    if len(sorted_indices) == 0:
        # We have no thresholds
        sorted_indices = [0]

    precision = np.array(techniques[technique]['precision'])[sorted_indices]
    recall = np.array(techniques[technique]['recall'])[sorted_indices]

    threshold = np.array(techniques[technique]['threshold'])[sorted_indices] if len(sorted_indices) > 1 else []
    
    if len(precision) == 1:
        j = 0
        plt.plot(precision[j], recall[j], marker=markers[i], color="red", linestyle="", alpha=0.7, label=technique)
    else:
        for j in range(len(precision) - 1):  # -1 to prevent index out of range in the next step
            # Get the color corresponding to the threshold
            color = colormap(norm(threshold[j]))
            
            # Plot the line segment
            plt.plot(precision[j:j+2], recall[j:j+2], marker=markers[i], markersize=3, linestyle=linestyles[i], color=color, alpha=0.5, label=technique if j == 0 else "")

            #plt.annotate(f'T={threshold[j]:.2f}', (precision[j], recall[j]), textcoords='offset points', xytext=(5,5))

# Create a colorbar to show the mapping from thresholds to colors
sm = cm.ScalarMappable(cmap=colormap, norm=norm)
sm.set_array([])
plt.colorbar(sm, label='Threshold')

plt.xlim([0, 1])
plt.ylim([0, 1])
plt.xlabel('Precision')
plt.ylabel('Recall')
plt.title('Precision vs. Recall')
plt.legend()
plt.grid(True)
plt.savefig(sys.argv[5], dpi=300)

# Create a CSV
#csvdata = (x for (_, _, _, _, _, _) in all_comparisons)
import csv
with open("/tmp/csv.csv", 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile, lineterminator="\n")
    csvwriter.writerows([("addr1", "addr2", "pichasheq", "ljdz_sim", "lev_sim", "ground_eq")] + all_comparisons)

from bokeh.plotting import figure, show, output_file
from bokeh.models import ColumnDataSource, HoverTool, BoxAnnotation, Span
from bokeh.layouts import gridplot
from bokeh.io import save
import numpy as np

def generate_interactive_violin_plot(data, filename, threshold=0.75):
    # Separate data based on ground_eq
    grouped_data = {
        'lev_sim': {
            True: [item for item in data if item[5]],
            False: [item for item in data if not item[5]]
        },
        'pichasheq': {
            True: [item for item in data if item[5]],
            False: [item for item in data if not item[5]]
        },
        'ljdz_sim': {
            True: [item for item in data if item[5]],
            False: [item for item in data if not item[5]]
        }
    }

    plots = []

    for metric, sub_data in grouped_data.items():
        for ground_truth, values in sub_data.items():
            p = figure(title=f'{metric} - ground_eq: {ground_truth}', 
                       tools="", background_fill_color="#EFE8E2", x_range=[0, 2], width=400, height=400)

            # Data for this plot
            y_values = [item[4] if metric == 'lev_sim' else float(item[2]) if metric == 'pichasheq' else item[3] for item in values]
            colors = ['green' if (y > threshold) == ground_truth else 'red' for y in y_values]
            addr1_values = [item[0] for item in values]
            addr2_values = [item[1] for item in values]

            source = ColumnDataSource(data=dict(y=y_values, color=colors, addr1=addr1_values, addr2=addr2_values))

            # Violin plot (represented as area between upper and lower quartile and line for the median)
            q1 = np.percentile(y_values, 25)
            q3 = np.percentile(y_values, 75)
            iqr = q3 - q1
            upper = min(max(y_values), q3 + 1.5*iqr)
            lower = max(min(y_values), q1 - 1.5*iqr)
            p.segment(1, upper, 1, q3, line_width=2, line_color="black", line_dash="dashed")
            p.segment(1, lower, 1, q1, line_width=2, line_color="black", line_dash="dashed")
            p.vbar(x=1, width=0.7, bottom=q1, top=q3, fill_color="#3B8686", line_color="black")
            p.circle(x='color', y='y', color='color', size=6, source=source, alpha=0.6)

            # Hover tool
            hover = HoverTool()
            hover.tooltips = [
                ("addr1", "@addr1"),
                ("addr2", "@addr2"),
                (metric, "@y")
            ]
            p.add_tools(hover)

            # Line at threshold
            p.line([0, 2], [threshold, threshold], line_dash="dashed", color="grey")

            # Annotations
            box_annotation_above = BoxAnnotation(bottom=threshold, fill_alpha=0.1, fill_color='green')
            box_annotation_below = BoxAnnotation(top=threshold, fill_alpha=0.1, fill_color='red')
            p.add_layout(box_annotation_above)
            p.add_layout(box_annotation_below)

            plots.append(p)

    # Organize the plots in a grid
    grid = gridplot([plots[i:i+3] for i in range(0, len(plots), 3)])
    
    # Output to static file (this can be modified as needed)
    #output_file(filename)

    # Display the plot
    #show(grid, notebook_handle=False)
    save(grid, filename=filename)

def violin_plot(data, fname):
    # Separate the values based on ground_eq
    lev_sim_true = [item[4] for item in data if item[5]]
    lev_sim_false = [item[4] for item in data if not item[5]]

    pichasheq_true = [float(item[2]) for item in data if item[5]]
    pichasheq_false = [float(item[2]) for item in data if not item[5]]

    ljdz_sim_true = [item[3] for item in data if item[5]]
    ljdz_sim_false = [item[3] for item in data if not item[5]]

    best_lzjd = get_best_threshold('lzjd')
    best_lev = get_best_threshold('lev')
    best_hash = get_best_threshold('pic')
    #print(f"Best LZJD Threshold: {best_lzjd}")
    #print(f"Best LEV Threshold: {best_lev}")

    # Group data for the plots
    plot_data = {
        'lev_sim': [lev_sim_true, lev_sim_false, best_lev['threshold'], best_lev['f1']],
        'pichasheq': [pichasheq_true, pichasheq_false, 0.5, best_hash['f1']],
        'ljdz_sim': [ljdz_sim_true, ljdz_sim_false, best_lzjd['threshold'], best_lzjd['f1']]
    }

    # Function to apply jitter
    def jitter_points(points, position, jitter_strength=0.15):
        jitter = jitter_strength * np.random.randn(len(points))
        return [position + j for j in jitter]
    
    # Colors for the points based on value and ground_eq
    def get_colors(values, ground_true, threshold):
        if ground_true:
            return ['green' if v > threshold else 'red' for v in values]
        else:
            return ['red' if v > threshold else 'green' for v in values]
        
    # Function to count points above and below 0.75 and determine their colors
    def count_points(data, ground_true, threshold):
        above = sum(1 for point in data if point > threshold)
        below = len(data) - above
        
        if ground_true:
            above_color, below_color = 'green', 'red'
        else:
            above_color, below_color = 'red', 'green'
        
        return above, below, above_color, below_color

    # Create the combined plots
    fig, axes = plt.subplots(nrows=1, ncols=3, figsize=(18, 6))

    # Positions for the boxplots, aligning them with the violin plots
    positions = [1, 2]

    for idx, (label, data) in enumerate(plot_data.items()):

        threshold = data[2]
        f1 = data[3]
        data = data[:2]

        # Violin plot
        axes[idx].violinplot(data, showmeans=True, showmedians=True, positions=positions, widths=0.6)
        
        # Box plot overlayed on top of the violin plot
        axes[idx].boxplot(data, positions=positions, vert=True, widths=0.3)

        # Jittered scatter plots with custom colors
        axes[idx].scatter(jitter_points(data[0], positions[0]), data[0], marker='o', color=get_colors(data[0], True, threshold), s=5, alpha=0.5)
        axes[idx].scatter(jitter_points(data[1], positions[1]), data[1], marker='o', color=get_colors(data[1], False, threshold), s=5, alpha=0.5)
        
        # Line across the plot at y=threshold
        axes[idx].axhline(y=threshold, color='gray', linestyle='--')

         # Add annotations for count of points above and below threshold with respective colors
        above_true, below_true, at_color, bt_color = count_points(data[0], True, threshold)
        above_false, below_false, af_color, bf_color = count_points(data[1], False, threshold)
        
        axes[idx].annotate(f'Above: {above_true}', (positions[0], threshold + 0.02), ha='center', color=at_color)
        axes[idx].annotate(f'Below: {below_true}', (positions[0], threshold - 0.02), ha='center', color=bt_color)
        axes[idx].annotate(f'Above: {above_false}', (positions[1], threshold + 0.02), ha='center', color=af_color)
        axes[idx].annotate(f'Below: {below_false}', (positions[1], threshold - 0.02), ha='center', color=bf_color)
        
        axes[idx].annotate(f'F1: {f1:.2}', xy=(0.5, 0.5), xycoords='axes fraction', ha='center', va='center', fontsize=10)

        axes[idx].set_title(f'Violin, Box, and Scatter plot of {label} based on ground_eq')
        axes[idx].set_ylabel(f'{label} value')
        axes[idx].set_xlabel('Equivalent in Ground truth')
        axes[idx].set_xticks(positions)
        axes[idx].set_xticklabels(['True', 'False'])
        axes[idx].set_ylim(0, 1)

    plt.tight_layout()

    # Save the figure to 'violin.png' with a resolution of 300 dpi
    plt.savefig(fname, dpi=300)

violin_plot(all_comparisons, sys.argv[6])
# doesn't work :()
#generate_interactive_violin_plot(all_comparisons, "omg.html")