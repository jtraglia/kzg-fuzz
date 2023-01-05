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
		BytesToBlsField(bytes32)
	})
}

func FuzzComputeAggregateKzgProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		cKzgBlobs := []Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		for i := 0; i < 5; i++ {
			cKzgBlob, goKzgBlob, ok := GetRandBlob(data)
			if !ok {
				break
			}
			cKzgBlobs = append(cKzgBlobs, cKzgBlob)
			goKzgBlobs = append(goKzgBlobs, goKzgBlob)
		}

		cKzgProof, ret := ComputeAggregateKzgProof(cKzgBlobs)
		goKzgProof, err := gokzg.ComputeAggregateKZGProof(goKzgBlobs)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, ret == 0, err == nil)
		if ret == 0 && err == nil {
			require.Equal(t, cKzgProof[:], goKzgProof[:])
		}
	})
}

func FuzzVerifyAggregateKzgProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		cKzgProof, goKzgProof, ok := GetRandProof(data)
		if !ok {
			t.SkipNow()
		}

		cKzgBlobs := []Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		cKzgCommitments := []Commitment{}
		goKzgCommitments := gokzg.KZGCommitmentSequenceImpl{}

		for i := 0; i < 5; i++ {
			cKzgBlob, goKzgBlob, ok := GetRandBlob(data)
			if !ok {
				break
			}
			cKzgCommitment, goKzgCommitment, ok := GetRandCommitment(data)
			if !ok {
				break
			}

			cKzgBlobs = append(cKzgBlobs, cKzgBlob)
			goKzgBlobs = append(goKzgBlobs, goKzgBlob)
			cKzgCommitments = append(cKzgCommitments, cKzgCommitment)
			goKzgCommitments = append(goKzgCommitments, goKzgCommitment)
		}

		cKzgResult, ret := VerifyAggregateKzgProof(cKzgBlobs, cKzgCommitments, cKzgProof)
		goKzgResult, err := gokzg.VerifyAggregateKZGProof(goKzgBlobs, goKzgCommitments, goKzgProof)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, ret == 0, err == nil)
		require.Equal(t, cKzgResult, goKzgResult)
	})
}

func FuzzBlobToKzgCommitment(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		cKzgBlob, goKzgBlob, ok := GetRandBlob(data)
		if !ok {
			t.SkipNow()
		}

		cKzgCommitment, cKzgRet := BlobToKzgCommitment(cKzgBlob)
		goKzgCommitment, goKzgRet := gokzg.BlobToKZGCommitment(goKzgBlob)

		require.Equal(t, cKzgRet == 0, goKzgRet == true)
		if cKzgRet == 0 && goKzgRet == true {
			require.Equal(t, cKzgCommitment[:], goKzgCommitment[:])
		}
	})
}

func FuzzVerifyKzgProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		cKzgCommitment, goKzgCommitment, ok := GetRandCommitment(data)
		if !ok {
			t.SkipNow()
		}
		cKzgProof, goKzgProof, ok := GetRandProof(data)
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

		var cKzgZ [bytesPerFieldElement]byte
		copy(cKzgZ[:], zBytes)
		var cKzgY [bytesPerFieldElement]byte
		copy(cKzgY[:], yBytes)

		var goKzgZ [32]byte
		copy(goKzgZ[:], zBytes)
		var goKzgY [32]byte
		copy(goKzgY[:], yBytes)

		cKzgResult, ret := VerifyKzgProof(cKzgCommitment, cKzgZ, cKzgY, cKzgProof)
		goKzgResult, err := gokzg.VerifyKZGProof(goKzgCommitment, goKzgZ, goKzgY, goKzgProof)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, ret == 0, err == nil)
		if ret == 0 && err == nil {
			require.Equal(t, cKzgResult, goKzgResult)
		}
	})
}
