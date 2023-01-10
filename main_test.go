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

var commitment1 = [48]byte{
	0x89, 0xce, 0x9d, 0x12, 0xc7, 0x63, 0x99, 0xdf, 0xa4, 0x8e, 0x66, 0x37,
	0x2a, 0xcb, 0x96, 0xcb, 0xfc, 0x91, 0x1b, 0xed, 0x66, 0x77, 0xe9, 0x2c,
	0x6f, 0x72, 0xad, 0xc5, 0xe8, 0x2e, 0x6f, 0x1f, 0xb3, 0xea, 0x98, 0xe3,
	0xad, 0xc3, 0x2e, 0x7a, 0xf1, 0x57, 0xe6, 0x22, 0x92, 0x5d, 0x74, 0x85}
var commitment2 = [48]byte{
	0x8e, 0xeb, 0xa7, 0xec, 0xf0, 0x82, 0x97, 0xc3, 0x99, 0x5d, 0x33, 0x56,
	0xec, 0x48, 0xb6, 0xe6, 0x5a, 0x79, 0x8b, 0xc7, 0x5c, 0xac, 0x4c, 0xad,
	0xad, 0xf8, 0x62, 0x71, 0x1b, 0xcc, 0x23, 0x0a, 0x5d, 0x64, 0x7d, 0xa9,
	0x87, 0xa3, 0x7c, 0x06, 0x0d, 0x61, 0x63, 0xae, 0xc5, 0xe7, 0xf3, 0xb8}
var commitment3 = [48]byte{
	0x8b, 0xa5, 0x6f, 0x7c, 0x6b, 0x6c, 0x89, 0xc1, 0x87, 0x5b, 0xb8, 0xb9,
	0xd5, 0x40, 0xa1, 0xc0, 0x2e, 0x73, 0xef, 0x4a, 0x40, 0x0c, 0xc7, 0x2e,
	0x28, 0xde, 0x34, 0x18, 0xd0, 0xe5, 0xdc, 0x84, 0x5b, 0x14, 0x7b, 0xa7,
	0x98, 0x43, 0x22, 0xf9, 0x81, 0x22, 0x69, 0x44, 0x61, 0x99, 0x76, 0x0a}

var proof = [48]byte{
	0xb8, 0x96, 0x35, 0xe5, 0x1d, 0x8c, 0xef, 0x87, 0xa0, 0x43, 0xb5, 0x7d,
	0x99, 0xfe, 0x8d, 0xf0, 0xf5, 0x20, 0x79, 0x1a, 0x65, 0x1c, 0xbb, 0x37,
	0x9d, 0x07, 0xb6, 0x3d, 0xa8, 0x6a, 0x89, 0x30, 0x25, 0x6f, 0x32, 0x9a,
	0x8a, 0x21, 0x2c, 0xb6, 0xad, 0x8b, 0x33, 0xb4, 0x0f, 0x76, 0x56, 0xb1}

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
