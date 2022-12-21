import time
from Crypto.PublicKey import ECC
from Crypto.Random import random


def hash_to_curve(num, key):
    return key._curve.G * num


def blind(_in, pubkey, random_number):
    return _in + pubkey._curve.G * random_number  # _in + r * G


def unblind(_in, pubkey, random_number):
    return _in + (-pubkey.pointQ * random_number)  # _in - r * Q


def sign(_in, prikey):
    return _in * prikey.d  # d * _in


private_key = ECC.generate(curve='p256')
public_key = private_key.public_key()

# 点击监测
# begin = time.time()
# for i in range(1000):
pa = hash_to_curve(38654201, public_key)
epa = sign(pa, private_key)
# end = time.time()
# nanos = (end - begin) * 1e9 / 1000
# print('time: ' + str(nanos) + 'ns')

# 2. 客户加盲
rand = random.randint(0, 0xffffffff)
bpa = blind(pa, public_key, rand)

# 3. 字节加密
ebpa = sign(bpa, private_key)

# 4. 客户解盲
bebpa = unblind(ebpa, public_key, rand)
assert bebpa == epa
