package fuzz

import (
	"math/rand"

	gokzgApi "github.com/crate-crypto/go-proto-danksharding-crypto/api"
	gokzg "github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
	ckzg "github.com/ethereum/c-kzg-4844/bindings/go"
	"github.com/holiman/uint256"
	fuzzutils "github.com/trailofbits/go-fuzz-utils"
)

func GetTypeProvider(data []byte) (*fuzzutils.TypeProvider, error) {
	tp, err := fuzzutils.NewTypeProvider(data)
	if err != nil {
		return nil, err
	}
	return tp, nil
}

func GetRandFieldElement(tp *fuzzutils.TypeProvider) (ckzg.Bytes32, [32]byte, bool) {
	seed, err := tp.GetInt64()
	if err != nil {
		return ckzg.Bytes32{}, [32]byte{}, false
	}

	rand.Seed(seed)
	fieldElementBytes := make([]byte, ckzg.BytesPerFieldElement)
	_, err = rand.Read(fieldElementBytes)
	if err != nil {
		return ckzg.Bytes32{}, [32]byte{}, false
	}
	var cKzgFieldElement ckzg.Bytes32

	if seed%2 == 0 {
		// Provide a completely random field element.
		copy(cKzgFieldElement[:], fieldElementBytes[:])
		return cKzgFieldElement, cKzgFieldElement, true
	} else {
		// Provide a valid/canonical field element.
		var BlsModulus = new(uint256.Int)
		BlsModulus.SetBytes(gokzgApi.MODULUS[:])
		field := new(uint256.Int).SetBytes(fieldElementBytes[:])
		field = field.Mod(field, BlsModulus)
		canonicalFieldElementBytes := field.Bytes32()

		copy(cKzgFieldElement[:], canonicalFieldElementBytes[:])
		return cKzgFieldElement, canonicalFieldElementBytes, true
	}
}

func GetRandCanonicalFieldElement(tp *fuzzutils.TypeProvider) (ckzg.Bytes32, [32]byte, bool) {
	seed, err := tp.GetInt64()
	if err != nil {
		return ckzg.Bytes32{}, [32]byte{}, false
	}

	rand.Seed(seed)
	fieldElementBytes := make([]byte, ckzg.BytesPerFieldElement)
	_, err = rand.Read(fieldElementBytes)
	if err != nil {
		return ckzg.Bytes32{}, [32]byte{}, false
	}
	var BlsModulus = new(uint256.Int)
	BlsModulus.SetBytes(gokzgApi.MODULUS[:])
	field := new(uint256.Int).SetBytes(fieldElementBytes[:])
	field = field.Mod(field, BlsModulus)
	canonicalFieldElementBytes := field.Bytes32()

	var cKzgFieldElement ckzg.Bytes32
	copy(cKzgFieldElement[:], canonicalFieldElementBytes[:])
	return cKzgFieldElement, canonicalFieldElementBytes, true
}

func GetRandBlob(tp *fuzzutils.TypeProvider) (ckzg.Blob, gokzg.Blob, bool) {
	seed, err := tp.GetInt64()
	if err != nil {
		return ckzg.Blob{}, gokzg.Blob{}, false
	}
	rand.Seed(seed)

	if seed%2 == 0 {
		// Provide a completely random blob.
		randomBytes := make([]byte, ckzg.BytesPerBlob)
		_, err = rand.Read(randomBytes)
		if err != nil {
			return ckzg.Blob{}, gokzg.Blob{}, false
		}
		var cKzgBlob ckzg.Blob
		copy(cKzgBlob[:], randomBytes)
		var goKzgBlob gokzg.Blob
		copy(goKzgBlob[:], randomBytes)
		return cKzgBlob, goKzgBlob, true
	} else {
		// Provide a valid/canonical blob.
		var cKzgBlob ckzg.Blob
		var goKzgBlob gokzg.Blob
		for i := 0; i < ckzg.BytesPerBlob; i += ckzg.BytesPerFieldElement {
			_, canonicalFieldElementBytes, ok := GetRandCanonicalFieldElement(tp)
			if !ok {
				return ckzg.Blob{}, gokzg.Blob{}, false
			}
			copy(cKzgBlob[i:i+ckzg.BytesPerFieldElement], canonicalFieldElementBytes[:])
			copy(goKzgBlob[i:i+ckzg.BytesPerFieldElement], canonicalFieldElementBytes[:])
		}
		return cKzgBlob, goKzgBlob, true
	}
}

func GetRandG1(tp *fuzzutils.TypeProvider) ([]byte, bool) {
	seed, err := tp.GetInt64()
	if err != nil {
		return []byte{}, false
	}
	rand.Seed(seed)

	if seed%2 == 0 {
		// Provide a completely random g1 point.
		randomBytes := make([]byte, 48)
		_, err = rand.Read(randomBytes)
		if err != nil {
			return []byte{}, false
		}
		return randomBytes, true
	} else {
		// Provide a valid/canonical g1 point.
		blob, _, ok := GetRandBlob(tp)
		if ok != false {
			return []byte{}, false
		}
		commitment, err := ckzg.BlobToKZGCommitment(blob)
		if err != nil {
			return []byte{}, false
		}
		return commitment[:], true
	}
}

func GetRandCommitment(tp *fuzzutils.TypeProvider) (ckzg.Bytes48, gokzg.KZGCommitment, bool) {
	commitmentBytes, ok := GetRandG1(tp)
	if !ok {
		return ckzg.Bytes48{}, gokzg.KZGCommitment{}, false
	}
	var cKzgCommitment ckzg.Bytes48
	copy(cKzgCommitment[:], commitmentBytes)
	var goKzgCommitment gokzg.KZGCommitment
	copy(goKzgCommitment[:], commitmentBytes)
	return cKzgCommitment, goKzgCommitment, true
}

func GetRandProof(tp *fuzzutils.TypeProvider) (ckzg.Bytes48, gokzg.KZGProof, bool) {
	proofBytes, ok := GetRandG1(tp)
	if !ok {
		return ckzg.Bytes48{}, gokzg.KZGProof{}, false
	}
	var cKzgProof ckzg.Bytes48
	copy(cKzgProof[:], proofBytes)
	var goKzgProof gokzg.KZGProof
	copy(goKzgProof[:], proofBytes)
	return cKzgProof, goKzgProof, true
}
