import numpy as np
import pandas as pd
import re
import glob
from scipy.stats import shapiro
from dataclasses import dataclass
from sklearn.preprocessing import LabelEncoder

def test_normality(data, column_name):
    stat, p = shapiro(data[column_name])
    alpha = 0.05
    if p > alpha:
        return True
    else:
        return False

@dataclass
class NormalizeSolution :
    is_normal: bool
    min_val: float
    mean_after_min: float
    std_after_min: float
    category: bool
    cat_enc: LabelEncoder
    raw: bool = False

    def apply(self, col) :
        if self.category :
            return self.cat_enc.transform(col)
            #return col.astype('category')
        if self.raw :
            return col
        if self.is_normal :
            v = (col - self.mean_after_min) / (self.std_after_min + 1e-6)
            if v.isnull().values.any() :
                #breakpoint()
                raise Exception
            return v
        else :
            col = np.log1p(np.maximum(col - self.min_val, 0))
            v = (col - self.mean_after_min) / (self.std_after_min + 1e-6)
            if v.isnull().values.any() :
                #breakpoint()
                raise Exception
            return v

def create_solution(data, column_name, method = 'all'):
    print('creating normalize solution for', column_name)
    if column_name in ['Feat 0', 'Feat 1'] :
        le = LabelEncoder()
        le.fit_transform(data[column_name])
        return NormalizeSolution(False, 0, 0, 0, True, le)
        
    if method == 'all' :
        n = test_normality(data, column_name)
        if not n :
            mv = np.min(data[column_name])
            data[column_name] = np.log1p(data[column_name] - mv)
            return NormalizeSolution(False, mv, np.mean(data[column_name]), np.std(data[column_name]), False, None)
        else :
            m = np.mean(data[column_name])
            return NormalizeSolution(True, 0, m, np.std(data[column_name]), False, None)
    elif method == 'nolog' :
        m = np.mean(data[column_name])
        return NormalizeSolution(True, 0, m, np.std(data[column_name]), False, None)
    elif method == 'none' :
        return NormalizeSolution(True, 0, 0, 0, False, None, raw = True)

