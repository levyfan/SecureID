import time
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random


def blind(_in, pubkey, random_number):
    return (_in * pow(pubkey.g, random_number, pubkey.p)) % pubkey.p


def unblind(_in, pubkey, random_number):
    ax = pow(pubkey.y, random_number, pubkey.p)
    return (_in * ax.inverse(pubkey.p)) % pubkey.p


def sign(_in, prikey):
    return pow(_in, prikey.x, prikey.p)


private_key = ElGamal.generate(768, get_random_bytes)
public_key = private_key.publickey()

pa = Integer(38654201)
# 点击监测
# begin = time.time()
# for i in range(1000):
epa = sign(pa, private_key)
# end = time.time()
# nanos = (end - begin) * 1e9 / 1000
# print('time: ' + str(nanos) + 'ns')

# 2. 客户加盲
rand = Integer(random.randint(0, 0xffffffff))
bpa = blind(pa, public_key, rand)

# 3. 字节加密
ebpa = sign(bpa, private_key)

# 4. 客户解盲
bebpa = unblind(ebpa, public_key, rand)
assert bebpa == epa
