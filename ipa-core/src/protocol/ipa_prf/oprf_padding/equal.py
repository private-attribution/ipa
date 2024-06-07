import numpy as np
import random


p1 = 0.3
p2 = 0.15
numsamples = 1000000

x_1 = np.random.geometric(p1,numsamples)
x_2 = np.random.geometric(p1,numsamples)

# compute first as X_1 - X_2
first = x_1 - x_2

firstcounts = {}
for d in first:
    if d in firstcounts:
        firstcounts[d] +=1
    else:
        firstcounts[d] = 1


# compute second as X_3 * (1 - 2 * Z)
second = []
for i in range(numsamples):
    z = bool(random.getrandbits(1))
    x_3 = np.random.geometric(p2)

    second.append(x_3 * (1 - 2 * z))

secondcounts = {}
for d in second:
    if d in secondcounts:
        secondcounts[d] +=1
    else:
        secondcounts[d] = 1

bound = 80
for i in range(-bound,bound+1):
    if i not in firstcounts:
        firstcounts[i] = 0
    if i not in secondcounts:
        secondcounts[i] = 0

for i in range(-bound,bound+1):
    # print(i,firstcounts[i],secondcounts[i],firstcounts[i] - secondcounts[i])
    print(i,firstcounts[i] - secondcounts[i])
