package fuzz

import (
    "bytes"
    gokzg "github.com/protolambda/go-kzg/eth"
    "os"
    "testing"

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
            return
        }
        g1Bytes, err := tp.GetNBytes(48)
        if err != nil {
            return
        }

        var bytes48 [48]byte
        copy(bytes48[:], g1Bytes)

        g1, ret := BytesToG1(bytes48)
        t.Log(g1, ret)
    })
}

func FuzzBytesFromG1(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        g1Bytes, err := tp.GetNBytes(g1Size)
        if err != nil {
            return
        }

        var g1 [g1Size]byte
        copy(g1[:], g1Bytes)

        result := BytesFromG1(g1)
        t.Log(result)
    })
}

func FuzzBytesToBlsField(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        blsFieldBytes, err := tp.GetNBytes(bytesPerFieldElement)
        if err != nil {
            return
        }

        var bytes32 [bytesPerFieldElement]byte
        copy(bytes32[:], blsFieldBytes)

        blsField, ret := BytesToBlsField(bytes32)
        t.Log(blsField, ret)
    })
}

func FuzzComputeAggregateKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        blobs := []Blob{}
        goKzgBlobs := []GoKzgBlobImpl{}
        for i := 0; i < 5; i++ {
            blobBytesPart, err := tp.GetNBytes(32)
            if err != nil {
                break
            }
            t.Logf("Blob #%v: %v\n", i, blobBytesPart)
            blobBytes := bytes.Repeat(blobBytesPart, 4096)

            var blob Blob
            copy(blob[:], blobBytes)
            blobs = append(blobs, blob)
            goKzgBlob := GoKzgBlobImpl(blobBytes)
            goKzgBlobs = append(goKzgBlobs, goKzgBlob)
        }

        expectedProof, expectedRet := ComputeAggregateKzgProof(blobs)
        goKzgBlobSequence := GoKzgBlobSequenceImpl(goKzgBlobs)
        proof, err := gokzg.ComputeAggregateKZGProof(goKzgBlobSequence)
        require.Equal(t, expectedRet == 0, err == nil)

        // If there's an error, gokzg will return all zeros whereas ckzg will
        // return the identity point. This is because gokzg returns the
        // compressed point and ckzg returns the uncompressed point which we
        // then compress.
        if expectedRet == 0 && err == nil {
            require.Equal(t, expectedProof[:], proof[:])
        }
    })
}

func FuzzVerifyAggregateKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }

        // This is generated first because we want to use the remaining random
        // bytes for the blobs and commitments.
        proofBytes, err := tp.GetNBytes(proofSize)
        if err != nil {
            return
        }

        blobsBytes := [][]byte{}
        commitmentsBytes := [][]byte{}
        for {
            blobBytesPart, err := tp.GetNBytes(32)
            if err != nil {
                break
            }
            blobBytes := bytes.Repeat(blobBytesPart, 4096)
            commitmentBytes, err := tp.GetNBytes(commitmentSize)
            if err != nil {
                break
            }

            blobsBytes = append(blobsBytes, blobBytes)
            commitmentsBytes = append(commitmentsBytes, commitmentBytes)
        }

        blobs := []Blob{}
        commitments := []Commitment{}
        for _, blobBytes := range blobsBytes {
            var blob Blob
            copy(blob[:], blobBytes)
            blobs = append(blobs, blob)
        }
        for _, commitmentBytes := range commitmentsBytes {
            var commitment Commitment
            copy(commitment[:], commitmentBytes)
            commitments = append(commitments, commitment)
        }
        var proof Proof
        copy(proof[:], proofBytes)
        expectedResult, expectedRet := VerifyAggregateKzgProof(blobs, commitments, proof)

        goKzgBlobs := []GoKzgBlobImpl{}
        for _, blobBytes := range blobsBytes {
            goKzgBlob := GoKzgBlobImpl(blobBytes)
            goKzgBlobs = append(goKzgBlobs, goKzgBlob)
        }
        goKzgBlobSequence := GoKzgBlobSequenceImpl(goKzgBlobs)
        goKzgCommitments := gokzg.KZGCommitmentSequenceImpl{}
        for _, commitmentBytes := range commitmentsBytes {
            var goKzgCommitment gokzg.KZGCommitment
            copy(goKzgCommitment[:], commitmentBytes)
            goKzgCommitments = append(goKzgCommitments, goKzgCommitment)
        }
        var goKzgProof gokzg.KZGProof
        copy(goKzgProof[:], proofBytes)
        result, err := gokzg.VerifyAggregateKZGProof(goKzgBlobSequence, goKzgCommitments, goKzgProof)

        require.Equal(t, expectedRet == 0, err == nil)
        require.Equal(t, expectedResult, result)
    })
}

func FuzzBlobToKzgCommitment(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        blobBytesPart, err := tp.GetNBytes(32)
        if err != nil {
            return
        }
        blobBytes := bytes.Repeat(blobBytesPart, 4096)
        require.Len(t, blobBytes, blobSize)

        t.Log(blobBytesPart)

        var blob Blob
        copy(blob[:], blobBytes)
        expectedCommitment, expectedRet := BlobToKzgCommitment(blob)

        goKzgBlob := GoKzgBlobImpl(blobBytes)
        commitment, ret := gokzg.BlobToKZGCommitment(goKzgBlob)

        require.Equal(t, expectedRet == 0, ret == true)
        if expectedRet == 0 && ret == true {
            require.Equal(t, expectedCommitment[:], commitment[:])
        }
    })
}

func FuzzVerifyKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        compressedCommitment, uncompressedCommitment, success := GetRandCommitment(data)
        if success == false {
            return
        }
        compressedProof, uncompressedProof, success := GetRandProof(data)
        if success == false {
            return
        }

        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        zBytes, err := tp.GetNBytes(bytesPerFieldElement)
        if err != nil {
            return
        }
        yBytes, err := tp.GetNBytes(bytesPerFieldElement)
        if err != nil {
            return
        }

        var z [bytesPerFieldElement]byte
        copy(z[:], zBytes)
        var y [bytesPerFieldElement]byte
        copy(y[:], yBytes)
        expectedResult, expectedRet := VerifyKzgProof(uncompressedCommitment, z, y, uncompressedProof)

        var goKzgCommitment gokzg.KZGCommitment
        copy(goKzgCommitment[:], compressedCommitment)
        var goKzgZ [32]byte
        copy(goKzgZ[:], zBytes)
        var goKzgY [32]byte
        copy(goKzgY[:], yBytes)
        var goKzgProof gokzg.KZGProof
        copy(goKzgProof[:], compressedProof)
        result, err := gokzg.VerifyKZGProof(goKzgCommitment, goKzgZ, goKzgY, goKzgProof)

        t.Log(err)
        require.Equal(t, expectedRet == 0, err == nil)
        if expectedRet == 0 && err == nil {
            require.Equal(t, expectedResult, result)
        }
    })
}
