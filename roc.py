#!/usr/bin/python3

import matplotlib.pyplot as plt
import pandas
import sys
from sklearn.metrics import roc_curve, roc_auc_score

d = pandas.read_csv(sys.argv[1], names=["correct", "name1", "name2", "sim", "lev"])

y_true = d["correct"]
y_pred = d["sim"]

fpr, tpr, thresholds = roc_curve(y_true, y_pred)

roc_auc = roc_auc_score(y_true, y_pred)

plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve')

# Annotate the points with thresholds
for i, threshold in enumerate(thresholds):
    plt.annotate(f'Threshold = {threshold:.2f}', (fpr[i], tpr[i]), textcoords='offset points', xytext=(5,5), ha='left', alpha=0.2)

plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.savefig(sys.argv[2], format='png')
plt.close()
