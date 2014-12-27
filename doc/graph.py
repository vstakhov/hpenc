#!/usr/bin/env python

import sys, os

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.cm as cm
from matplotlib.ticker import EngFormatter

data = np.loadtxt(sys.argv[1])

mode = int(sys.argv[2]);

fig, ax = plt.subplots()
ax.grid(True)

if mode == 0:
    formatter = EngFormatter(places=0,unit='B')
    plt.title('Encryption throughtput from the block size')
    ax.set_xlabel('Block size')
    ax.set_xscale('symlog', basex=2)
    plt.axvline(x=16384, ls='--', label='SSL record size')
    ax.xaxis.set_major_formatter(formatter)
else:
    plt.title('Encryption throughtput from the CPU cores count')
    ax.set_xlabel('Cores count')

ax.set_ylabel('Throughput mbits/second')

plt.plot(data[:,0], data[:,1], 'o-', label='AES-128-GCM')
plt.plot(data[:,0], data[:,2], 'x-', label='AES-256-GCM')
plt.plot(data[:,0], data[:,3], '^-', label='Chacha20-Poly1305')
ax.legend(loc=4)
plt.show()
