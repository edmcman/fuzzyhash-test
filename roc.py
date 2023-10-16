#!/usr/bin/python3

import matplotlib.pyplot as plt
import pandas
import sys
from sklearn.metrics import roc_curve, roc_auc_score

d = pandas.read_csv(sys.argv[1], names=["strategy", "correct", "name1", "name2", "sim", "lev"])

lzjd = d[d["strategy"] == "PLOTLZJD"]
fse = d[d["strategy"] == "PLOTFSE"]

lzjd_true, lzjd_pred = lzjd["correct"], lzjd["sim"]
fse_true, fse_pred = fse["correct"], fse["sim"]

# Anything >= threshold is considered the same.
def eds_roc_curve(T, P):
    thresholds = sorted(set(P) | {0.0, 1.0})
    accs = {threshold: sum(t == (p >= threshold) for (t,p) in zip(T,P)) / float(len(P)) for threshold in thresholds}

    #aboves = {threshold: sum(1 for (t,p) in zip(T,P) if p >= threshold) for threshold in thresholds}
    # ratio of positives that are above the threshold
    #tp = {threshold: sum(t and (p >= threshold) for (t,p) in zip(T,P)) / aboves[threshold] for threshold in thresholds}

    # ratio of negatives above the threshold
    #fps = {threshold: sum(not t and (p >= threshold) for (t,p) in zip(T,P)) / aboves[threshold] for threshold in thresholds}

    #print(tps)
    #print(fps)

    #print(pos)
    return accs
    #print(total)

#eds_roc_curve(lzjd_true, lzjd_pred)

#lzjd_fpr, lzjd_tpr, lzjd_thresholds = roc_curve(lzjd_true, lzjd_pred, pos_label=True)
#fse_fpr, fse_tpr, fse_thresholds = roc_curve(fse_true, fse_pred, pos_label=True)

lzjd_curve = eds_roc_curve(lzjd_true, lzjd_pred)
fse_curve = eds_roc_curve(fse_true, fse_pred)

#print(lzjd_tpr, lzjd_fpr)
#print(fse_tpr, fse_fpr)

#import ipdb
#ipdb.set_trace()

#roc_auc = roc_auc_score(lzjd_true, lzjd_pred)

plt.figure(figsize=(8, 6))

plt.plot(lzjd_curve.keys(), lzjd_curve.values(), color='darkorange', lw=2, label='LZJD accuracy curve')

plt.plot(fse_curve.keys(), fse_curve.values(), color='darkred', lw=2, label='FSE accuracy curve')


# Annotate the points with thresholds
#last_y = -1000
#for i, threshold in enumerate(lzjd_thresholds):
#    diff = lzjd_tpr[i] - last_y
#    # hand tuned constant
#    if diff > 0.07:
#        last_y = lzjd_tpr[i]
#

#plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('Similarity threshold')
plt.ylabel('Accuracy')
plt.title('Threshold-Accuracy Curve')
plt.legend(loc='lower right')
plt.savefig(sys.argv[2], format='png')
plt.close()
