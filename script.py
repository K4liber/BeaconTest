import numpy as np
from math import pow

def calcDist(rssi, freq):
    exp = (27.55 - (20 * np.log10(freq)) + abs(rssi)) / 20.0
    return pow(10.0, exp)

m1 = [-51, -49, -37, -44, -42, -43, -43, -41, -43, -43]

m1mean = np.mean(m1)
print(m1mean)
print(calcDist(m1mean, 2412))