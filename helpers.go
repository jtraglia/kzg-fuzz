package fuzz

import (
    bls12381 "github.com/jtraglia/bls12-381"
    go_fuzz_utils "github.com/trailofbits/go-fuzz-utils"
)

func GetTypeProvider(data []byte) (*go_fuzz_utils.TypeProvider, error) {
    tp, err := go_fuzz_utils.NewTypeProvider(data)
    if err != nil {
        return nil, err
    }
    return tp, nil
}

func GetRandG1(data []byte) ([]byte, []byte, bool) {
    tp, err := GetTypeProvider(data)
    if err != nil {
        return []byte{}, []byte{}, false
    }

    zBytes, err := tp.GetNBytes(48)
    if err != nil {
        return []byte{}, []byte{}, false
    }

    g1 := bls12381.NewG1()
    g1Point := g1.New()

    for {
        xBytes, err := tp.GetNBytes(48)
        if err != nil {
            return []byte{}, []byte{}, false
        }
        g1Point := g1.RandCorrect(zBytes, xBytes)
        if g1Point != nil {
            break
        }
    }

    if g1 == nil || g1Point == nil {
        return []byte{}, []byte{}, false
    }
    compressedBytes := g1.ToCompressed(g1Point)
    compressed := [48]byte{}
    copy(compressed[:], compressedBytes)
    uncompressedBytes, ret := BytesToG1(compressed)
    if ret != 0 {
        panic("invalid g1 point")
    }
    return compressedBytes, uncompressedBytes[:], true
}

func GetRandCommitment(data []byte) ([]byte, Commitment, bool) {
    compressed, uncompressed, success := GetRandG1(data)
    if success == false {
        return []byte{}, Commitment{}, false
    }
    var commitment Commitment
    copy(commitment[:], uncompressed)
    return compressed, commitment, true
}

func GetRandProof(data []byte) ([]byte, Proof, bool) {
    compressed, uncompressed, success := GetRandG1(data)
    if success == false {
        return []byte{}, Proof{}, false
    }
    var proof Proof
    copy(proof[:], uncompressed)
    return compressed, proof, true
}
