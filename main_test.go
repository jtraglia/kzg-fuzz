package fuzz

import (
	"os"
	"testing"

	gokzg "github.com/protolambda/go-kzg/eth"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	ret := LoadTrustedSetupFile("c-kzg-4844/src/trusted_setup.txt")
	if ret != 0 {
		panic("Failed to load trusted setup")
	}
	code := m.Run()
	FreeTrustedSetup()
	os.Exit(code)
}

func FuzzBytesToG1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		compressedBytes, err := tp.GetNBytes(compressedG1Size)
		if err != nil {
			t.SkipNow()
		}

		var compressed [compressedG1Size]byte
		copy(compressed[:], compressedBytes)
		BytesToG1(compressed)
	})
}

func FuzzBytesFromG1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		g1Bytes, err := tp.GetNBytes(g1StructSize)
		if err != nil {
			t.SkipNow()
		}

		var g1 [g1StructSize]byte
		copy(g1[:], g1Bytes)
		BytesFromG1(g1)
	})
}

func FuzzRoundTripG1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		compressedBytes, err := tp.GetNBytes(compressedG1Size)
		if err != nil {
			t.SkipNow()
		}

		var compressed [compressedG1Size]byte
		copy(compressed[:], compressedBytes)

		g1, ret := BytesToG1(compressed)
		if ret == 0 {
			result := BytesFromG1(g1)
			require.Equal(t, compressed, result)
		}
	})
}

func FuzzBytesToBlsField(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		blsFieldBytes, err := tp.GetNBytes(bytesPerFieldElement)
		if err != nil {
			t.SkipNow()
		}

		var bytes32 [bytesPerFieldElement]byte
		copy(bytes32[:], blsFieldBytes)

		blsField, ret := BytesToBlsField(bytes32)
		t.Log(blsField, ret)
	})
}

func FuzzComputeAggregateKzgProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		blobs := []Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		for i := 0; i < 5; i++ {
			blob, ok := GetRandBlob(data)
			if !ok {
				break
			}

			blobs = append(blobs, blob)
			goKzgBlob := GoKzgBlobImpl(blob[:])
			goKzgBlobs = append(goKzgBlobs, goKzgBlob)
		}

		expectedProof, expectedRet := ComputeAggregateKzgProof(blobs)
		proof, err := gokzg.ComputeAggregateKZGProof(goKzgBlobs)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, expectedRet == 0, err == nil)
		if expectedRet == 0 && err == nil {
			require.Equal(t, expectedProof[:], proof[:])
		}
	})
}

func FuzzVerifyAggregateKzgProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		compressedProof, uncompressedProof, ok := GetRandProof(data)
		if !ok {
			t.SkipNow()
		}

		blobs := []Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		compressedCommitments := gokzg.KZGCommitmentSequenceImpl{}
		uncompressedCommitments := []Commitment{}

		for i := 0; i < 5; i++ {
			blob, ok := GetRandBlob(data)
			if !ok {
				break
			}
			compressedCommitment, uncompressedCommitment, ok := GetRandCommitment(data)
			if !ok {
				break
			}

			blobs = append(blobs, blob)
			goKzgBlob := GoKzgBlobImpl(blob[:])
			goKzgBlobs = append(goKzgBlobs, goKzgBlob)
			compressedCommitments = append(compressedCommitments, compressedCommitment)
			uncompressedCommitments = append(uncompressedCommitments, uncompressedCommitment)
		}

		expectedResult, expectedRet := VerifyAggregateKzgProof(blobs, uncompressedCommitments, uncompressedProof)
		result, err := gokzg.VerifyAggregateKZGProof(goKzgBlobs, compressedCommitments, compressedProof)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, expectedRet == 0, err == nil)
		require.Equal(t, expectedResult, result)
	})
}

func FuzzBlobToKzgCommitment(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		blob, ok := GetRandBlob(data)
		if !ok {
			t.SkipNow()
		}

		goKzgBlob := GoKzgBlobImpl(blob[:])
		expectedCommitment, expectedRet := BlobToKzgCommitment(blob)
		commitment, ret := gokzg.BlobToKZGCommitment(goKzgBlob)

		require.Equal(t, expectedRet == 0, ret == true)
		if expectedRet == 0 && ret == true {
			require.Equal(t, expectedCommitment[:], commitment[:])
		}
	})
}

func FuzzVerifyKzgProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		compressedCommitment, uncompressedCommitment, ok := GetRandCommitment(data)
		if !ok {
			t.SkipNow()
		}
		compressedProof, uncompressedProof, ok := GetRandProof(data)
		if !ok {
			t.SkipNow()
		}

		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		zBytes, err := tp.GetNBytes(bytesPerFieldElement)
		if err != nil {
			t.SkipNow()
		}
		yBytes, err := tp.GetNBytes(bytesPerFieldElement)
		if err != nil {
			t.SkipNow()
		}

		var z [bytesPerFieldElement]byte
		copy(z[:], zBytes)
		var y [bytesPerFieldElement]byte
		copy(y[:], yBytes)

		var goKzgZ [32]byte
		copy(goKzgZ[:], zBytes)
		var goKzgY [32]byte
		copy(goKzgY[:], yBytes)

		expectedResult, expectedRet := VerifyKzgProof(uncompressedCommitment, z, y, uncompressedProof)
		result, err := gokzg.VerifyKZGProof(compressedCommitment, goKzgZ, goKzgY, compressedProof)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, expectedRet == 0, err == nil)
		if expectedRet == 0 && err == nil {
			require.Equal(t, expectedResult, result)
		}
	})
}
