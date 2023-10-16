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

lzjd_fpr, lzjd_tpr, lzjd_thresholds = roc_curve(lzjd_true, lzjd_pred)
fse_fpr, fse_tpr, fse_thresholds = roc_curve(fse_true, fse_pred)

roc_auc = roc_auc_score(lzjd_true, lzjd_pred)

plt.figure(figsize=(8, 6))
plt.plot(lzjd_fpr, lzjd_tpr, color='darkorange', lw=2, label='LZJD ROC curve')

plt.plot(fse_fpr, fse_tpr, color='darkred', lw=2, label='FSE ROC curve')


# Annotate the points with thresholds
last_y = -1000
for i, threshold in enumerate(lzjd_thresholds):
    diff = lzjd_tpr[i] - last_y
    # hand tuned constant
    if diff > 0.07:
        last_y = lzjd_tpr[i]
        plt.annotate(f'Threshold = {threshold:.2f}', (lzjd_fpr[i], lzjd_tpr[i]), textcoords='offset points', xytext=(5,5), ha='left')

plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.savefig(sys.argv[2], format='png')
plt.close()
