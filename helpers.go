package fuzz

import (
    bls12381 "github.com/jtraglia/bls12-381"
    go_fuzz_utils "github.com/trailofbits/go-fuzz-utils"
    "bytes"
    gokzg "github.com/protolambda/go-kzg/eth"
)

func GetTypeProvider(data []byte) (*go_fuzz_utils.TypeProvider, error) {
    tp, err := go_fuzz_utils.NewTypeProvider(data)
    if err != nil {
        return nil, err
    }
    return tp, nil
}

func GetRandBlob(data []byte) (Blob, bool) {
    tp, err := go_fuzz_utils.NewTypeProvider(data)
    if err != nil {
        return Blob{}, false
    }
    blobBytesPart, err := tp.GetNBytes(32)
    if err != nil {
        return Blob{}, false
    }
    blobBytes := bytes.Repeat(blobBytesPart, 4096)

    var blob Blob
    copy(blob[:], blobBytes)
    return blob, true
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

func GetRandCommitment(data []byte) (gokzg.KZGCommitment, Commitment, bool) {
    compressed, uncompressed, ok := GetRandG1(data)
    if !ok {
        return gokzg.KZGCommitment{}, Commitment{}, false
    }
    var compressedCommitment gokzg.KZGCommitment
    copy(compressedCommitment[:], compressed)
    var uncompressedCommitment Commitment
    copy(uncompressedCommitment[:], uncompressed)
    return compressedCommitment, uncompressedCommitment, true
}

func GetRandProof(data []byte) (gokzg.KZGProof, Proof, bool) {
    compressed, uncompressed, ok := GetRandG1(data)
    if !ok {
        return gokzg.KZGProof{}, Proof{}, false
    }
    var compressedProof gokzg.KZGProof
    copy(compressedProof[:], compressed)
    var uncompressedProof Proof
    copy(uncompressedProof[:], uncompressed)
    return compressedProof, uncompressedProof, true
}
