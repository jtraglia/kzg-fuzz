package fuzz

import (
	"os"
	"testing"

	ckzg "github.com/jtraglia/cgo-kzg-4844"
	"github.com/protolambda/go-kzg/bls"
	gokzg "github.com/protolambda/go-kzg/eth"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	ret := ckzg.LoadTrustedSetupFile("trusted_setup.txt")
	if ret != 0 {
		panic("Failed to load trusted setup")
	}
	code := m.Run()
	ckzg.FreeTrustedSetup()
	os.Exit(code)
}

///////////////////////////////////////////////////////////////////////////////
// C-KZG-4844 Specific Fuzzing Functions
///////////////////////////////////////////////////////////////////////////////

func FuzzBytesToG1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		compressedBytes, err := tp.GetNBytes(ckzg.CompressedG1Size)
		if err != nil {
			t.SkipNow()
		}

		var compressed [ckzg.CompressedG1Size]byte
		copy(compressed[:], compressedBytes)
		ckzg.BytesToG1(compressed)
	})
}

func FuzzBytesFromG1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		g1Bytes, err := tp.GetNBytes(ckzg.G1StructSize)
		if err != nil {
			t.SkipNow()
		}

		var g1 [ckzg.G1StructSize]byte
		copy(g1[:], g1Bytes)
		ckzg.BytesFromG1(g1)
	})
}

func FuzzRoundTripG1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		compressedBytes, err := tp.GetNBytes(ckzg.CompressedG1Size)
		if err != nil {
			t.SkipNow()
		}

		var compressed [ckzg.CompressedG1Size]byte
		copy(compressed[:], compressedBytes)

		g1, ret := ckzg.BytesToG1(compressed)
		if ret == 0 {
			result := ckzg.BytesFromG1(g1)
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
		blsFieldBytes, err := tp.GetNBytes(ckzg.BytesPerFieldElement)
		if err != nil {
			t.SkipNow()
		}

		var bytes32 [ckzg.BytesPerFieldElement]byte
		copy(bytes32[:], blsFieldBytes)
		ckzg.BytesToBlsField(bytes32)
	})
}

///////////////////////////////////////////////////////////////////////////////
// Go-KZG Specific Fuzzing Functions
///////////////////////////////////////////////////////////////////////////////

func FuzzKZGToVersionedHash(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		var goKzgCommitment gokzg.KZGCommitment
		input, err := tp.GetNBytes(len(goKzgCommitment))
		if err != nil {
			t.SkipNow()
		}
		copy(goKzgCommitment[:], input)
		gokzg.KZGToVersionedHash(goKzgCommitment)
	})
}

func FuzzTxPeekBlobVersionedHashes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < gokzg.BlobVersionedHashesOffset+4 {
			t.SkipNow()
		}
		data[0] = gokzg.BlobTxType
		gokzg.TxPeekBlobVersionedHashes(data)
	})
}

func FuzzPointEvaluationPrecompile(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		input, err := tp.GetNBytes(gokzg.PrecompileInputLength)
		if err != nil {
			t.SkipNow()
		}
		gokzg.PointEvaluationPrecompile(input)
	})
}

func FuzzEvaluatePolynomialInEvaluationForm(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		poly := []bls.Fr{}
		for i := 0; i < 4096; i++ {
			var fr bls.Fr
			err = tp.Fill(&fr)
			if err != nil {
				t.SkipNow()
			}
			poly = append(poly, fr)
		}
		var x bls.Fr
		err = tp.Fill(&x)
		if err != nil {
			t.SkipNow()
		}
		gokzg.EvaluatePolynomialInEvaluationForm(poly, &x)
	})
}

///////////////////////////////////////////////////////////////////////////////
// Differential Fuzzing Functions
///////////////////////////////////////////////////////////////////////////////

func FuzzComputeAggregateKzgProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		cKzgBlobs := []ckzg.Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		for i := 0; i < 5; i++ {
			cKzgBlob, goKzgBlob, ok := GetRandBlob(data)
			if !ok {
				break
			}
			cKzgBlobs = append(cKzgBlobs, cKzgBlob)
			goKzgBlobs = append(goKzgBlobs, goKzgBlob)
		}

		cKzgProof, ret := ckzg.ComputeAggregateKzgProof(cKzgBlobs)
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

		cKzgBlobs := []ckzg.Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		cKzgCommitments := []ckzg.Commitment{}
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

		cKzgResult, ret := ckzg.VerifyAggregateKzgProof(cKzgBlobs, cKzgCommitments, cKzgProof)
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

		cKzgCommitment, cKzgRet := ckzg.BlobToKzgCommitment(cKzgBlob)
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
		zBytes, err := tp.GetNBytes(ckzg.BytesPerFieldElement)
		if err != nil {
			t.SkipNow()
		}
		yBytes, err := tp.GetNBytes(ckzg.BytesPerFieldElement)
		if err != nil {
			t.SkipNow()
		}

		var cKzgZ [ckzg.BytesPerFieldElement]byte
		copy(cKzgZ[:], zBytes)
		var cKzgY [ckzg.BytesPerFieldElement]byte
		copy(cKzgY[:], yBytes)

		var goKzgZ [32]byte
		copy(goKzgZ[:], zBytes)
		var goKzgY [32]byte
		copy(goKzgY[:], yBytes)

		cKzgResult, ret := ckzg.VerifyKzgProof(cKzgCommitment, cKzgZ, cKzgY, cKzgProof)
		goKzgResult, err := gokzg.VerifyKZGProof(goKzgCommitment, goKzgZ, goKzgY, goKzgProof)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, ret == 0, err == nil)
		if ret == 0 && err == nil {
			require.Equal(t, cKzgResult, goKzgResult)
		}
	})
}

///////////////////////////////////////////////////////////////////////////////
// Benchmarks
///////////////////////////////////////////////////////////////////////////////

var blob1 = ckzg.Blob{1, 2, 3}
var blob2 = ckzg.Blob{4, 5, 6}
var blob3 = ckzg.Blob{7, 8, 9}

var commitment1 = [48]byte{137, 206, 157, 18, 199, 99, 153, 223, 164, 142, 102, 55, 42, 203, 150, 203, 252, 145, 27,
	237, 102, 119, 233, 44, 111, 114, 173, 197, 232, 46, 111, 31, 179, 234, 152, 227, 173, 195, 46, 122, 241, 87, 230,
	34, 146, 93, 116, 133}
var commitment2 = [48]byte{142, 235, 167, 236, 240, 130, 151, 195, 153, 93, 51, 86, 236, 72, 182, 230, 90, 121, 139,
	199, 92, 172, 76, 173, 173, 248, 98, 113, 27, 204, 35, 10, 93, 100, 125, 169, 135, 163, 124, 6, 13, 97, 99, 174,
	197, 231, 243, 184}
var commitment3 = [48]byte{139, 165, 111, 124, 107, 108, 137, 193, 135, 91, 184, 185, 213, 64, 161, 192, 46, 115, 239,
	74, 64, 12, 199, 46, 40, 222, 52, 24, 208, 229, 220, 132, 91, 20, 123, 167, 152, 67, 34, 249, 129, 34, 105, 68, 97,
	153, 118, 10}

var proof = [48]byte{184, 150, 53, 229, 29, 140, 239, 135, 160, 67, 181, 125, 153, 254, 141, 240, 245, 32, 121, 26,
	101, 28, 187, 55, 157, 7, 182, 61, 168, 106, 137, 48, 37, 111, 50, 154, 138, 33, 44, 182, 173, 139, 51, 180, 15,
	118, 86, 177}

var z = [32]byte{1, 2, 3}
var y = [32]byte{4, 5, 6}

func BenchmarkBytesFromG1(b *testing.B) {
	var g1 = [ckzg.G1StructSize]byte{}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ckzg.BytesFromG1(g1)
	}
}

func BenchmarkBytesToG1(b *testing.B) {
	var g1Bytes = [ckzg.CompressedG1Size]byte{192}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, ret := ckzg.BytesToG1(g1Bytes)
		require.Equal(b, 0, ret)
	}
}

func BenchmarkBytesToBlsField(b *testing.B) {
	var blsFieldBytes = [ckzg.BytesPerFieldElement]byte{}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, ret := ckzg.BytesToBlsField(blsFieldBytes)
		require.Equal(b, 0, ret)
	}
}

func BenchmarkComputeAggregateKzgProofCkzg(b *testing.B) {
	cKzgBlobs := []ckzg.Blob{blob1, blob2, blob3}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, ret := ckzg.ComputeAggregateKzgProof(cKzgBlobs)
		require.Equal(b, 0, ret)
	}
}

func BenchmarkComputeAggregateKzgProofGokzg(b *testing.B) {
	goKzgBlobs := GoKzgBlobSequenceImpl{blob1[:], blob2[:], blob3[:]}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err := gokzg.ComputeAggregateKZGProof(goKzgBlobs)
		require.NoError(b, err)
	}
}

func BenchmarkVerifyAggregateKzgProofCkzg(b *testing.B) {
	cKzgBlobs := []ckzg.Blob{blob1, blob2, blob3}
	cKzgCommitments := []ckzg.Commitment{}
	cKzgCommitment1, ret := ckzg.BytesToG1(commitment1)
	require.Equal(b, 0, ret)
	cKzgCommitments = append(cKzgCommitments, cKzgCommitment1)
	cKzgCommitment2, ret := ckzg.BytesToG1(commitment2)
	require.Equal(b, 0, ret)
	cKzgCommitments = append(cKzgCommitments, cKzgCommitment2)
	cKzgCommitment3, ret := ckzg.BytesToG1(commitment3)
	require.Equal(b, 0, ret)
	cKzgCommitments = append(cKzgCommitments, cKzgCommitment3)
	cKzgProof, ret := ckzg.BytesToG1(proof)
	require.Equal(b, 0, ret)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, ret := ckzg.VerifyAggregateKzgProof(cKzgBlobs, cKzgCommitments, cKzgProof)
		require.Equal(b, 0, ret)
	}
}

func BenchmarkVerifyAggregateKzgProofGokzg(b *testing.B) {
	goKzgBlobs := GoKzgBlobSequenceImpl{blob1[:], blob2[:], blob3[:]}
	goKzgCommitments := gokzg.KZGCommitmentSequenceImpl{commitment1, commitment2, commitment3}
	goKzgProof := gokzg.KZGProof(proof)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err := gokzg.VerifyAggregateKZGProof(goKzgBlobs, goKzgCommitments, goKzgProof)
		require.NoError(b, err)
	}
}

func BenchmarkBlobToKzgCommitmentCkzg(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, ret := ckzg.BlobToKzgCommitment(blob1)
		require.Equal(b, 0, ret)
	}
}

func BenchmarkBlobToKzgCommitmentGokzg(b *testing.B) {
	goKzgBlob := GoKzgBlobImpl(blob1[:])

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, ret := gokzg.BlobToKZGCommitment(goKzgBlob)
		require.Equal(b, true, ret)
	}
}

func BenchmarkVerifyKzgProofCkzg(b *testing.B) {
	cKzgCommitment, ret := ckzg.BytesToG1(commitment1)
	require.Equal(b, 0, ret)
	var cKzgZ [ckzg.BytesPerFieldElement]byte
	copy(cKzgZ[:], z[:])
	var cKzgY [ckzg.BytesPerFieldElement]byte
	copy(cKzgY[:], y[:])
	cKzgProof, ret := ckzg.BytesToG1(proof)
	require.Equal(b, 0, ret)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, ret := ckzg.VerifyKzgProof(cKzgCommitment, cKzgZ, cKzgY, cKzgProof)
		require.Equal(b, 0, ret)
	}
}

func BenchmarkVerifyKzgProofGokzg(b *testing.B) {
	goKzgCommitment := gokzg.KZGCommitment(commitment1)
	goKzgProof := gokzg.KZGProof(proof)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err := gokzg.VerifyKZGProof(goKzgCommitment, z, y, goKzgProof)
		require.Equal(b, nil, err)
	}
}
