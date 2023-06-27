package fuzz

import (
	"math/rand"
	"testing"

	gokzg "github.com/crate-crypto/go-kzg-4844"
	ckzg "github.com/ethereum/c-kzg-4844/bindings/go"
	"github.com/holiman/uint256"
)

type Action int64

const (
	actionRandom  Action = 0
	actionValid   Action = 1
	actionMutated Action = 2
)

func Mutate(data []byte, seed int64) []byte {
	rand.Seed(seed)
	/* Mutate at most 1% of the bits */
	count := int(float32(rand.Intn(len(data)*8)) * 0.01)
	for i := 0; i < count; i++ {
		index := rand.Intn(len(data))
		bitPosition := uint(rand.Intn(8))
		data[index] ^= 1 << bitPosition
	}
	return data
}

func GetRandFieldElement(t *testing.T, seed int64) (ckzg.Bytes32, [32]byte, bool) {
	t.Helper()
	rand.Seed(seed)
	fieldElementBytes := make([]byte, ckzg.BytesPerFieldElement)
	_, err := rand.Read(fieldElementBytes)
	if err != nil {
		return ckzg.Bytes32{}, [32]byte{}, false
	}
	var cKzgFieldElement ckzg.Bytes32

	action := Action(seed % 3)
	if action == actionRandom {
		// Provide a completely random field element.
		copy(cKzgFieldElement[:], fieldElementBytes[:])
		return cKzgFieldElement, cKzgFieldElement, true
	} else {
		// Provide a valid/canonical field element.
		var BlsModulus = new(uint256.Int)
		BlsModulus.SetBytes(gokzg.BlsModulus[:])
		field := new(uint256.Int).SetBytes(fieldElementBytes[:])
		field = field.Mod(field, BlsModulus)
		canonicalFieldElementBytes := field.Bytes32()

		// Mutate the data, which may make it invalid.
		if action == actionMutated {
			mutateSeed := rand.Int63()
			mutated := Mutate(canonicalFieldElementBytes[:], mutateSeed)
			copy(canonicalFieldElementBytes[:], mutated)
		}

		copy(cKzgFieldElement[:], canonicalFieldElementBytes[:])
		return cKzgFieldElement, canonicalFieldElementBytes, true
	}
}

func GetRandCanonicalFieldElement(t *testing.T, seed int64) (ckzg.Bytes32, [32]byte, bool) {
	t.Helper()
	rand.Seed(seed)
	fieldElementBytes := make([]byte, ckzg.BytesPerFieldElement)
	_, err := rand.Read(fieldElementBytes)
	if err != nil {
		return ckzg.Bytes32{}, [32]byte{}, false
	}
	var BlsModulus = new(uint256.Int)
	BlsModulus.SetBytes(gokzg.BlsModulus[:])
	field := new(uint256.Int).SetBytes(fieldElementBytes[:])
	field = field.Mod(field, BlsModulus)
	canonicalFieldElementBytes := field.Bytes32()

	var cKzgFieldElement ckzg.Bytes32
	copy(cKzgFieldElement[:], canonicalFieldElementBytes[:])
	return cKzgFieldElement, canonicalFieldElementBytes, true
}

func GetRandBlob(t *testing.T, seed int64) (ckzg.Blob, gokzg.Blob, bool) {
	t.Helper()
	rand.Seed(seed)

	action := Action(seed % 3)
	if action == actionRandom {
		// Provide a completely random blob.
		randomBytes := make([]byte, ckzg.BytesPerBlob)
		_, err := rand.Read(randomBytes)
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
			newSeed := rand.Int63()
			_, canonicalFieldElementBytes, ok := GetRandCanonicalFieldElement(t, newSeed)
			if !ok {
				return ckzg.Blob{}, gokzg.Blob{}, false
			}

			// Mutate the data, which may make it invalid.
			if action == actionMutated {
				mutateSeed := rand.Int63()
				mutated := Mutate(canonicalFieldElementBytes[:], mutateSeed)
				copy(canonicalFieldElementBytes[:], mutated)
			}

			copy(cKzgBlob[i:i+ckzg.BytesPerFieldElement], canonicalFieldElementBytes[:])
			copy(goKzgBlob[i:i+ckzg.BytesPerFieldElement], canonicalFieldElementBytes[:])
		}
		return cKzgBlob, goKzgBlob, true
	}
}

func GetRandG1(t *testing.T, seed int64) ([]byte, bool) {
	t.Helper()
	rand.Seed(seed)

	action := Action(seed % 3)
	if action == actionRandom {
		// Provide a completely random g1 point.
		randomBytes := make([]byte, 48)
		_, err := rand.Read(randomBytes)
		if err != nil {
			return []byte{}, false
		}
		return randomBytes, true
	} else {
		// Provide a valid/canonical g1 point.
		blob, _, ok := GetRandBlob(t, seed)
		if ok != false {
			return []byte{}, false
		}
		commitment, err := ckzg.BlobToKZGCommitment(blob)

		// Mutate the data, which may make it invalid.
		if action == actionMutated {
			mutateSeed := rand.Int63()
			mutated := Mutate(commitment[:], mutateSeed)
			copy(commitment[:], mutated)
		}

		if err != nil {
			return []byte{}, false
		}
		return commitment[:], true
	}
}

func GetRandCommitment(t *testing.T, seed int64) (ckzg.Bytes48, gokzg.KZGCommitment, bool) {
	t.Helper()
	commitmentBytes, ok := GetRandG1(t, seed)
	if !ok {
		return ckzg.Bytes48{}, gokzg.KZGCommitment{}, false
	}
	var cKzgCommitment ckzg.Bytes48
	copy(cKzgCommitment[:], commitmentBytes)
	var goKzgCommitment gokzg.KZGCommitment
	copy(goKzgCommitment[:], commitmentBytes)
	return cKzgCommitment, goKzgCommitment, true
}

func GetRandProof(t *testing.T, seed int64) (ckzg.Bytes48, gokzg.KZGProof, bool) {
	t.Helper()
	proofBytes, ok := GetRandG1(t, seed)
	if !ok {
		return ckzg.Bytes48{}, gokzg.KZGProof{}, false
	}
	var cKzgProof ckzg.Bytes48
	copy(cKzgProof[:], proofBytes)
	var goKzgProof gokzg.KZGProof
	copy(goKzgProof[:], proofBytes)
	return cKzgProof, goKzgProof, true
}
