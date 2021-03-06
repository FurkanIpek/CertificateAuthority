﻿import random
import sys

## Taken from wikipedia, develops rabin-miller primality test
def rm_primality(n, k = 7):
   if n < 6:  # assuming n >= 0 in all cases... shortcut small cases here
      return [False, False, True, True, False, True][n]
   elif n & 1 == 0:  # should be faster than n % 2
      return False
   else:
      s, d = 0, n - 1
      while d & 1 == 0:
         s, d = s + 1, d >> 1
      for a in random.sample(xrange(2, min(n - 2, sys.maxint)), min(n - 4, k)):
      #for a in range(randint(2, n-2)):
         x = pow(a, d, n)
         if x != 1 and x + 1 != n:
            for r in xrange(1, s):
               x = pow(x, 2, n)
               if x == 1:
                  return False  # composite for sure
               elif x == n - 1:
                  a = 0  # so we know loop didn't continue to end
                  break  # could be strong liar, try another a
            if a:
               return False  # composite if we reached end of this loop
      return True  # probably prime if reached end of outer loop


## Generates a string num_bits/8 bytes long
def generateKey(num_bits):
    key = ""

    for i in range(num_bits/8):
        temp = random.randint(1,2)

        if temp == 1:
            key += chr(random.randint(65, 90))
        else:
            key += chr(random.randint(97, 122))

    return key


## Generates random bits
def gen_random(bits):
    if bits > 0:
        return random.getrandbits(bits)
    else:
        return ''


def ceil(a, b):
    r = a / b

    if a > r * b:
        r += 1

    return r


## Modular expontiation: returns a**x % N
def mod_exp(a, x, N):
    return pow(a, x, N)


## Extended eucledian algorithm.
## finds x and y for the equation ax + by = 1 and also gcd of a and b
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

## inverse of e modulo N
def inverse(e, N):
    return egcd(e, N)[1] % N