package fuzz

import (
	bls12381 "github.com/jtraglia/bls12-381"
	gokzg "github.com/protolambda/go-kzg/eth"
	fuzzutils "github.com/trailofbits/go-fuzz-utils"
)

func GetTypeProvider(data []byte) (*fuzzutils.TypeProvider, error) {
	tp, err := fuzzutils.NewTypeProvider(data)
	if err != nil {
		return nil, err
	}
	return tp, nil
}

func GetRandBlob(data []byte) (Blob, GoKzgBlobImpl, bool) {
	tp, err := fuzzutils.NewTypeProvider(data)
	if err != nil {
		return Blob{}, GoKzgBlobImpl{}, false
	}
	randomUint, err := tp.GetUint()
	if err != nil {
		return Blob{}, GoKzgBlobImpl{}, false
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
	return blob, blob[:], true
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
	compressed := [compressedG1Size]byte{}
	copy(compressed[:], compressedBytes)
	cKzgG1Bytes, ret := BytesToG1(compressed)
	if ret != 0 {
		panic("invalid g1 point")
	}
	return cKzgG1Bytes[:], compressedBytes, true
}

func GetRandCommitment(data []byte) (Commitment, gokzg.KZGCommitment, bool) {
	cKzgCommitmentBytes, goKzgCommitmentBytes, ok := GetRandG1(data)
	if !ok {
		return Commitment{}, gokzg.KZGCommitment{}, false
	}
	var cKzgCommitment Commitment
	copy(cKzgCommitment[:], cKzgCommitmentBytes)
	var goKzgCommitment gokzg.KZGCommitment
	copy(goKzgCommitment[:], goKzgCommitmentBytes)
	return cKzgCommitment, goKzgCommitment, true
}

func GetRandProof(data []byte) (Proof, gokzg.KZGProof, bool) {
	cKzgProofBytes, goKzgProofBytes, ok := GetRandG1(data)
	if !ok {
		return Proof{}, gokzg.KZGProof{}, false
	}
	var cKzgProof Proof
	copy(cKzgProof[:], cKzgProofBytes)
	var goKzgProof gokzg.KZGProof
	copy(goKzgProof[:], goKzgProofBytes)
	return cKzgProof, goKzgProof, true
}
