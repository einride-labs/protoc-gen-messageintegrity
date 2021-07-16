import matplotlib.pyplot as plt
import matplotlib.cbook as cbook
import matplotlib

import numpy as np
import pandas as pd

font = {'family' : 'normal',
        'weight' : 'normal',
        'size'   : 18}

matplotlib.rc('font', **font)
data = pd.read_csv('eval_size_results_option_2048_rsa.csv')
data['signature percentage'] = 100*(data['signed size (bytes)'] - data['unsigned size (bytes)'])/data['signed size (bytes)']


print(data)
data.plot(0, 3, ylabel="signature % of payload", subplots=False)
plt.show()
