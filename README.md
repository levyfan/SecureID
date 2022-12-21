# SecureID

A faster implementation of ECC-based DID intersection than [SecureUnionID](https://github.com/volcengine/SecureUnionID)

# INSTALL

First, you should build and install [mcl](https://github.com/herumi/mcl) into system path

```shell
git clone https://github.com/herumi/mcl
cd mcl
make -j4
sudo make install
```

Then follow language guides below:

### C++

```shell
mkdir build
cd build
cmake ..
make test
```

### Go

```shell
cd go && go test SecureID -tags bn256
```

### Java

```shell
mvn clean test
```

### Python

```shell
python secure_id_test.py
```

# API

Checkout the unit tests for API usage.

# ECC-based PSI explained

G: base point

r: random number

P = hash_to_curve(raw_msg)

|         | PublicKey: Q=d*G | SecretKey: d |
|---------|------------------|--------------|
| sign1   |                  | S1 = d*P     |
| blind   | B = P + r*G      |              |
| sign2   |                  | S2 = d*B     |
| unblind | U = S2 - r*Q     |              |

U = d*(P + r*G) - r*d*G = S1

# Benchmark Result

```
Apple M1 Pro

BenchmarkSign1-10    	   17118	     68549 ns/op

Benchmark                  Mode  Cnt      Score      Error  Units
SecureIDBenchmark.bmSign1  avgt    5  67765.119 ± 1689.184  ns/op
```
