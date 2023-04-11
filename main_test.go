package fuzz

import (
	"math/rand"
	"os"
	"testing"

	gokzg "github.com/crate-crypto/go-kzg-4844"
	ckzg "github.com/ethereum/c-kzg-4844/bindings/go"
	"github.com/stretchr/testify/require"
)

var gokzgCtx *gokzg.Context

func TestMain(m *testing.M) {
	err := ckzg.LoadTrustedSetupFile("trusted_setup.txt")
	if err != nil {
		panic("Failed to load trusted setup")
	}
	gokzgCtx, err = gokzg.NewContext4096Insecure1337()
	if err != nil {
		panic("Failed to create context")
	}

	code := m.Run()

	ckzg.FreeTrustedSetup()
	os.Exit(code)
}

///////////////////////////////////////////////////////////////////////////////
// Differential Fuzzing Functions
///////////////////////////////////////////////////////////////////////////////

func FuzzBlobToKZGCommitment(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
		if !ok {
			t.SkipNow()
		}

		cKzgCommitment, cKzgErr := ckzg.BlobToKZGCommitment(cKzgBlob)
		goKzgCommitment, goKzgErr := gokzgCtx.BlobToKZGCommitment(goKzgBlob)

		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil {
			require.Equal(t, cKzgCommitment[:], goKzgCommitment[:])
		}
	})
}

func FuzzComputeKZGProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
		if !ok {
			t.SkipNow()
		}
		cKzgZ, goKzgZ, ok := GetRandFieldElement(tp)
		if !ok {
			t.SkipNow()
		}

		cKzgProof, cKzgY, cKzgErr := ckzg.ComputeKZGProof(cKzgBlob, cKzgZ)
		goKzgProof, goKzgY, goKzgErr := gokzgCtx.ComputeKZGProof(goKzgBlob, goKzgZ)

		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil {
			require.Equal(t, cKzgProof[:], goKzgProof[:])
			require.Equal(t, cKzgY[:], goKzgY[:])
		}
	})
}

func FuzzComputeBlobKZGProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
		if !ok {
			t.SkipNow()
		}
		cKzgCommitment, goKzgCommitment, ok := GetRandCommitment(tp)
		if !ok {
			t.SkipNow()
		}

		cKzgProof, cKzgErr := ckzg.ComputeBlobKZGProof(cKzgBlob, cKzgCommitment)
		goKzgProof, goKzgErr := gokzgCtx.ComputeBlobKZGProof(goKzgBlob, goKzgCommitment)

		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil {
			require.Equal(t, cKzgProof[:], goKzgProof[:])
		}
	})
}

func FuzzVerifyKZGProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgCommitment, goKzgCommitment, ok := GetRandCommitment(tp)
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
		cKzgProof, goKzgProof, ok := GetRandProof(tp)
		if !ok {
			t.SkipNow()
		}
		seed, err := tp.GetInt64()
		if err != nil {
			t.SkipNow()
		}
		rand.Seed(seed)

		if seed%2 == 0 {
			var cKzgErr, goKzgErr error
			var cKzgProofTrusted ckzg.KZGProof

			// Generate a blob that'll be used to make a commitment/proof
			cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
			if !ok {
				t.SkipNow()
			}

			// Generate a KZGCommitment to that blob
			cKzgCommitmentTrusted, cKzgErr := ckzg.BlobToKZGCommitment(cKzgBlob)
			goKzgCommitment, goKzgErr = gokzgCtx.BlobToKZGCommitment(goKzgBlob)
			require.Equal(t, cKzgErr == nil, goKzgErr == nil)
			if cKzgErr == nil && goKzgErr == nil {
				require.Equal(t, cKzgCommitment[:], goKzgCommitment[:])
			}

			// Generate a KZGProof to that blob/point
			cKzgProofTrusted, cKzgY, cKzgErr = ckzg.ComputeKZGProof(cKzgBlob, cKzgZ)
			goKzgProof, goKzgY, goKzgErr = gokzgCtx.ComputeKZGProof(goKzgBlob, goKzgZ)
			require.Equal(t, cKzgErr == nil, goKzgErr == nil)
			if cKzgErr == nil && goKzgErr == nil {
				require.Equal(t, cKzgProof[:], goKzgProof[:])
			}

			// Convert KZGCommitment/KZGProof to untrusted Bytes48s
			cKzgCommitment = ckzg.Bytes48(cKzgCommitmentTrusted)
			cKzgProof = ckzg.Bytes48(cKzgProofTrusted)
		}

		cKzgResult, cKzgErr := ckzg.VerifyKZGProof(cKzgCommitment, cKzgZ, cKzgY, cKzgProof)
		goKzgErr := gokzgCtx.VerifyKZGProof(goKzgCommitment, goKzgZ, goKzgY, goKzgProof)
		goKzgResult := err == nil

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil {
			require.Equal(t, cKzgResult, goKzgResult)
		}
	})
}

func FuzzVerifyBlobKZGProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		cKzgBlob, goKzgBlob, ok := GetRandBlob(tp)
		if !ok {
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
		seed, err := tp.GetInt64()
		if err != nil {
			t.SkipNow()
		}

		rand.Seed(seed)
		if seed%2 == 0 {
			var cKzgErr, goKzgErr error
			var cKzgProofTrusted ckzg.KZGProof

			// Generate a KZGProof to that blob/commitment
			cKzgProofTrusted, cKzgErr = ckzg.ComputeBlobKZGProof(cKzgBlob, cKzgCommitment)
			goKzgProof, goKzgErr = gokzgCtx.ComputeBlobKZGProof(goKzgBlob, goKzgCommitment)
			require.Equal(t, cKzgErr == nil, goKzgErr == nil)
			if cKzgErr == nil && goKzgErr == nil {
				require.Equal(t, cKzgProof[:], goKzgProof[:])
			}

			// Convert the KZGProof to an untrusted Bytes48
			cKzgProof = ckzg.Bytes48(cKzgProofTrusted)
		}

		cKzgResult, cKzgErr := ckzg.VerifyBlobKZGProof(cKzgBlob, cKzgCommitment, cKzgProof)
		goKzgErr := gokzgCtx.VerifyBlobKZGProof(goKzgBlob, goKzgCommitment, goKzgProof)
		goKzgResult := err == nil

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil {
			require.Equal(t, cKzgResult, goKzgResult)
		}
	})
}

func FuzzVerifyBlobKZGProofBatch(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := GetTypeProvider(data)
		if err != nil {
			t.SkipNow()
		}
		count, err := tp.GetUint()
		if err != nil {
			t.SkipNow()
		}

		// Between 1 and 5, inclusive
		count = (count % 5) + 1

		cKzgBlobs := make([]ckzg.Blob, count)
		cKzgCommitments := make([]ckzg.Bytes48, count)
		cKzgProofs := make([]ckzg.Bytes48, count)
		goKzgBlobs := make([]gokzg.Blob, count)
		goKzgCommitments := make([]gokzg.KZGCommitment, count)
		goKzgProofs := make([]gokzg.KZGProof, count)

		for i := 0; i < int(count); i++ {
			var cKzgBlob ckzg.Blob
			var cKzgCommitment ckzg.Bytes48
			var cKzgProof ckzg.Bytes48
			var goKzgBlob gokzg.Blob
			var goKzgCommitment gokzg.KZGCommitment
			var goKzgProof gokzg.KZGProof

			completelyRandom, err := tp.GetBool()
			if err != nil {
				t.SkipNow()
			}

			if completelyRandom {
				var ok bool
				cKzgBlob, goKzgBlob, ok = GetRandBlob(tp)
				if !ok {
					t.SkipNow()
				}
				cKzgCommitment, goKzgCommitment, ok = GetRandCommitment(tp)
				if !ok {
					t.SkipNow()
				}
				cKzgProof, goKzgProof, ok = GetRandProof(tp)
				if !ok {
					t.SkipNow()
				}
			} else {
				var cKzgErr, goKzgErr error
				var cKzgProofTrusted ckzg.KZGProof

				// Generate a KZGProof to that blob/commitment
				cKzgProofTrusted, cKzgErr = ckzg.ComputeBlobKZGProof(cKzgBlob, cKzgCommitment)
				goKzgProof, goKzgErr = gokzgCtx.ComputeBlobKZGProof(goKzgBlob, goKzgCommitment)
				require.Equal(t, cKzgErr == nil, goKzgErr == nil)
				if cKzgErr == nil && goKzgErr == nil {
					require.Equal(t, cKzgProof[:], goKzgProof[:])
				}

				// Convert the KZGProof to an untrusted Bytes48
				cKzgProof = ckzg.Bytes48(cKzgProofTrusted)
			}

			cKzgBlobs[i] = cKzgBlob
			cKzgCommitments[i] = cKzgCommitment
			cKzgProofs[i] = cKzgProof

			goKzgBlobs[i] = goKzgBlob
			goKzgCommitments[i] = goKzgCommitment
			goKzgProofs[i] = goKzgProof
		}

		cKzgResult, cKzgErr := ckzg.VerifyBlobKZGProofBatch(cKzgBlobs, cKzgCommitments, cKzgProofs)
		goKzgErr := gokzgCtx.VerifyBlobKZGProofBatch(goKzgBlobs, goKzgCommitments, goKzgProofs)
		goKzgResult := err == nil

		t.Logf("go-kzg error: %v\n", err)
		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil {
			require.Equal(t, cKzgResult, goKzgResult)
		}
	})
}
