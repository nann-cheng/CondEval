import sycret
import math
import numpy as np

n=32
x_y = 1<<28 
# x_y = 1<<28 

# How 
leFSS = sycret.LeFactory(n_threads=1)
k0, k1 = leFSS.keygen(1)
alpha = leFSS.alpha(k0,k1)[0].item()

print("alpha is ", alpha, " with ", math.log(alpha,2), " bits")

v_s=np.array([alpha-3])
mask = v_s.astype(np.int64)
s_0 = leFSS.eval(0, mask, k0)
s_1 = leFSS.eval(1, mask, k1)

# In PySyft, the AdditiveSharingTensor class will take care of the modulo
result = (s_0 + s_1) % (2 ** (leFSS.N * 8))

print(" result is: ", result)