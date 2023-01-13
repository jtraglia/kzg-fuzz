package fuzz

import (
	"math/rand"

	"github.com/holiman/uint256"
	ckzg "github.com/jtraglia/cgo-kzg-4844"
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

func GetRandBlob(tp *fuzzutils.TypeProvider) (ckzg.Blob, GoKzgBlobImpl, bool) {
	var BlsModulus = new(uint256.Int)
	BlsModulus.SetFromBig(gokzg.BLSModulus)

	_, fieldElementBytes, ok := GetRandFieldElement(tp)
	if !ok {
		return ckzg.Blob{}, GoKzgBlobImpl{}, false
	}
	var blob ckzg.Blob
	for i := 0; i < ckzg.BytesPerBlob; i += ckzg.BytesPerFieldElement {
		field := new(uint256.Int).SetBytes(fieldElementBytes[:])
		field = field.Mod(field, BlsModulus)
		copy(blob[i:i+ckzg.BytesPerFieldElement], field.Bytes())
	}
	return blob, blob[:], true
}

func GetRandG1(tp *fuzzutils.TypeProvider) ([]byte, bool) {
	blob, _, ok := GetRandBlob(tp)
	if ok != false {
		return []byte{}, false
	}
	commitment, ret := ckzg.BlobToKzgCommitment(blob)
	if ret != ckzg.Ok {
		return []byte{}, false
	}
	return commitment[:], true
}

func GetRandCommitment(tp *fuzzutils.TypeProvider) (ckzg.KZGCommitment, gokzg.KZGCommitment, bool) {
	commitmentBytes, ok := GetRandG1(tp)
	if !ok {
		return ckzg.KZGCommitment{}, gokzg.KZGCommitment{}, false
	}
	var cKzgCommitment ckzg.KZGCommitment
	copy(cKzgCommitment[:], commitmentBytes)
	var goKzgCommitment gokzg.KZGCommitment
	copy(goKzgCommitment[:], commitmentBytes)
	return cKzgCommitment, goKzgCommitment, true
}

func GetRandProof(tp *fuzzutils.TypeProvider) (ckzg.KZGProof, gokzg.KZGProof, bool) {
	proofBytes, ok := GetRandG1(tp)
	if !ok {
		return ckzg.KZGProof{}, gokzg.KZGProof{}, false
	}
	var cKzgProof ckzg.KZGProof
	copy(cKzgProof[:], proofBytes)
	var goKzgProof gokzg.KZGProof
	copy(goKzgProof[:], proofBytes)
	return cKzgProof, goKzgProof, true
}

func GetRandFieldElement(tp *fuzzutils.TypeProvider) (ckzg.BLSFieldElement, [32]byte, bool) {
	seed, err := tp.GetInt64()
	if err != nil {
		return ckzg.BLSFieldElement{}, [32]byte{}, false
	}

	rand.Seed(seed)
	fieldElementBytes := make([]byte, ckzg.BytesPerFieldElement)
	_, err = rand.Read(fieldElementBytes)
	if err != nil {
		return ckzg.BLSFieldElement{}, [32]byte{}, false
	}

	var cKzgFieldElement ckzg.BLSFieldElement
	copy(cKzgFieldElement[:], fieldElementBytes)
	var goKzgFieldElement [32]byte
	copy(goKzgFieldElement[:], fieldElementBytes)
	return cKzgFieldElement, goKzgFieldElement, true
}
