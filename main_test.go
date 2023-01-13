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
		if len(data) < gokzg.PrecompileInputLength {
			t.SkipNow()
		}
		gokzg.PointEvaluationPrecompile(data[:gokzg.PrecompileInputLength])
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
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}

		cKzgBlobs := []ckzg.Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		for i := 0; i < 5; i++ {
			cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
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
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgProof, goKzgProof, ok := GetRandProof(tp)
		if !ok {
			t.SkipNow()
		}

		cKzgBlobs := []ckzg.Blob{}
		goKzgBlobs := GoKzgBlobSequenceImpl{}
		cKzgCommitments := []ckzg.KZGCommitment{}
		goKzgCommitments := gokzg.KZGCommitmentSequenceImpl{}

		for i := 0; i < 5; i++ {
			cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
			if !ok {
				break
			}
			cKzgCommitment, goKzgCommitment, ok := GetRandCommitment(tp)
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
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
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
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgCommitment, goKzgCommitment, ok := GetRandCommitment(tp)
		if !ok {
			t.SkipNow()
		}
		cKzgProof, goKzgProof, ok := GetRandProof(tp)
		if !ok {
			t.SkipNow()
		}
		cKzgZ, goKzgZ, ok := GetRandFieldElement(tp)
		if !ok {
			t.SkipNow()
		}
		cKzgY, goKzgY, ok := GetRandFieldElement(tp)
		if !ok {
			t.SkipNow()
		}

		cKzgResult, ret := ckzg.VerifyKzgProof(cKzgCommitment, cKzgZ, cKzgY, cKzgProof)
		goKzgResult, err := gokzg.VerifyKZGProof(goKzgCommitment, goKzgZ, goKzgY, goKzgProof)

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, ret == 0, err == nil)
		if ret == 0 && err == nil {
			require.Equal(t, cKzgResult, goKzgResult)
		}
	})
}
