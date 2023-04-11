# KZG Fuzz

This repository has functions that fuzz the exported functions in
[c-kzg-4844](https://github.com/ethereum/c-kzg-4844) (c-kzg) and
[go-kzg-4844](https://github.com/crate-crypto/go-kzg-4844) (go-kzg). For several
of these functions, we compare implementation results given the same inputs; we
expect these to be the same.

## Fuzzing

To fuzz all functions for 5 minutes each perpetually, run this script:

```
./fuzz.sh
```
If you want to change the fuzzing time, override the `FUZZTIME` variable:

```
FUZZTIME=10m ./fuzz.sh
```

### Differential fuzzing tests

```
go test -fuzz=FuzzBlobToKZGCommitment
```
```
go test -fuzz=FuzzComputeKZGProof
```
```
go test -fuzz=FuzzComputeBlobKZGProof
```
```
go test -fuzz=FuzzVerifyKZGProof
```
```
go test -fuzz=FuzzVerifyBlobKZGProof
```
```
go test -fuzz=FuzzVerifyBlobKZGProofBatch
```

### Problems you may encounter

#### Too many open files

If you encounter an issue like this:
```
warning: starting with empty corpus
fuzz: elapsed: 0s, execs: 0 (0/sec), new interesting: 0 (total: 0)
fuzz: elapsed: 1s, execs: 0 (0/sec), new interesting: 0 (total: 0)
--- FAIL: FuzzVerifyBlobKZGProof (1.21s)
    open /dev/null: too many open files
FAIL
exit status 1
FAIL	fuzz	3.577s
```

Most likely, your system has a relatively low open file limit.
```
$ ulimit -n
1024
```

Raise that value by running the following command:
```
$ ulimit -n 100000
```

Now, try running the fuzzer again.

### Notes

* We use `TypeProvider#getNBytes` instead of `TypeProvider#Fill` because it's ~10 times faster.
  * This requires we `copy` the bytes, but it's still that much faster.
* For generating blobs, we use `bytes#Repeat` because it's rare to get 131,072+ bytes for fuzzing.
  * It would be nice to ask for that many random bytes and actually get it.
* When generating multiple blobs/commitments, we generate until we run out of bytes.
  * If we get a random `count` and try to generate that many, it will almost always fail.
