#!/usr/bin/python3

import matplotlib.pyplot as plt
import pandas
import sys
#import sklearn.metrics
from sklearn.metrics import RocCurveDisplay

d = pandas.read_csv(sys.argv[1], names=["correct", "name1", "name2", "sim", "lev"])

y_true = d["correct"]
y_pred = d["sim"]

RocCurveDisplay.from_predictions(y_true, y_pred)
plt.show()