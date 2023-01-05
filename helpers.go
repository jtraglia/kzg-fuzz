package fuzz

import (
	bls12381 "github.com/jtraglia/bls12-381"
	gokzg "github.com/protolambda/go-kzg/eth"
	go_fuzz_utils "github.com/trailofbits/go-fuzz-utils"
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
	randomUint, err := tp.GetUint()
	if err != nil {
		return Blob{}, false
	}

	var blob Blob
	numFieldElements := randomUint % 64
	for i := 0; i < int(numFieldElements); i += bytesPerFieldElement {
		// This adds a trailing zero to the field element. I'm not actually
		// sure if this is necessary. Also, if there's no more data,
		// return what we have. No need to waste a good test case.
		fieldElement, err := tp.GetNBytes(bytesPerFieldElement - 1)
		if err != nil {
			break
		}
		copy(blob[i:i+bytesPerFieldElement-1], fieldElement)
	}
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
