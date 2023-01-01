package goczkg

// #cgo CFLAGS: -g -Wall -Ic-kzg-4844/inc -DFIELD_ELEMENTS_PER_BLOB=4096
// #cgo LDFLAGS: -Lc-kzg-4844/lib -lblst
// #include <stdlib.h>
// #include "c-kzg-4844/src/c_kzg_4844.h"
// #include "c-kzg-4844/src/c_kzg_4844.c"
import "C"
import "unsafe"

const blobSize = C.BYTES_PER_BLOB
const commitmentSize = C.sizeof_KZGCommitment
const proofSize = C.sizeof_KZGProof
const g1Size = C.sizeof_g1_t
const g2Size = C.sizeof_g2_t
const bytesPerFieldElement = C.BYTES_PER_FIELD_ELEMENT

type Blob [blobSize]byte
type Commitment [commitmentSize]byte
type Proof [proofSize]byte

var loaded = false
var settings = C.KZGSettings{}

/*
BytesToG1 is the binding for:
    C_KZG_RET bytes_to_g1(
        g1_t* out,
        const uint8_t in[48]);
*/
func BytesToG1(bytes [48]byte) (C.g1_t, C.C_KZG_RET) {
    out := C.g1_t{}
    ret := C.bytes_to_g1(
        &out,
        (*C.uchar)(unsafe.Pointer(&bytes)))
    return out, ret
}

/*
BytesFromG1 is the binding for:
    void bytes_from_g1(
        uint8_t out[48],
        const g1_t *in);
*/
func BytesFromG1(g1 [g1Size]byte) [48]byte {
    var bytes [48]byte
    C.bytes_from_g1(
        (*C.uchar)(unsafe.Pointer(&bytes)),
        (*C.g1_t)(unsafe.Pointer(&g1)))
    return bytes
}

/*
BytesToBlsField is the binding for:
    C_KZG_RET bytes_to_bls_field(
        BLSFieldElement *out,
        const uint8_t in[BYTES_PER_FIELD_ELEMENT]);
*/
func BytesToBlsField(bytes [bytesPerFieldElement]byte) (C.BLSFieldElement, C.C_KZG_RET) {
    bls_field := C.BLSFieldElement{}
    ret := C.bytes_to_bls_field(
        &bls_field,
        (*C.uint8_t)(unsafe.Pointer(&bytes)))
    return bls_field, ret
}

/*
LoadTrustedSetup is the binding for:
    C_KZG_RET load_trusted_setup(
        KZGSettings *out,
        const uint8_t g1_bytes[], // n1 * 48 bytes
        size_t n1,
        const uint8_t g2_bytes[], // n2 * 96 bytes
        size_t n2);
*/
func LoadTrustedSetup(g1Bytes, g2Bytes []byte) C.C_KZG_RET {
    if loaded == true {
        panic("trusted setup is already loaded")
    }
    if len(g1Bytes)%48 != 0 {
        panic("len(g1Bytes) is not a multiple of 48")
    }
    if len(g2Bytes)%96 != 0 {
        panic("len(g2Bytes) is not a multiple of 96")
    }
    numG1Elements := len(g1Bytes) % 48
    numG2Elements := len(g1Bytes) % 96
    ret := C.load_trusted_setup(
        &settings,
        (*C.uint8_t)(unsafe.Pointer(&g1Bytes)),
        (C.size_t)(numG1Elements),
        (*C.uint8_t)(unsafe.Pointer(&g1Bytes)),
        (C.size_t)(numG2Elements))
    if ret == 0 {
        loaded = true
    }
    return ret
}

/*
LoadTrustedSetupFile is the binding for:
    C_KZG_RET load_trusted_setup_file(
        KZGSettings *out,
        FILE *in);
*/
func LoadTrustedSetupFile(trustedSetupFile string) C.C_KZG_RET {
    if loaded == true {
        panic("trusted setup is already loaded")
    }
    fp := C.fopen(C.CString(trustedSetupFile), C.CString("rb"))
    if fp == nil {
        panic("Error reading trusted setup")
    }
    ret := C.load_trusted_setup_file(&settings, fp)
    C.fclose(fp)
    if ret == 0 {
        loaded = true
    }
    return ret
}

/*
FreeTrustedSetup is the binding for:
    void free_trusted_setup(
        KZGSettings *s);
*/
func FreeTrustedSetup() {
    if loaded == false {
        panic("trusted setup isn't loaded")
    }
    C.free_trusted_setup(&settings)
}

/*
ComputeAggregateKzgProof is the binding for:
    C_KZG_RET compute_aggregate_kzg_proof(
        KZGProof *out,
        const Blob blobs[],
        size_t n,
        const KZGSettings *s);
*/
func ComputeAggregateKzgProof(blobs []Blob) (C.KZGProof, C.C_KZG_RET) {
    proof := C.KZGProof{}
    ret := C.compute_aggregate_kzg_proof(
        &proof,
        (*C.Blob)(unsafe.Pointer(&blobs)),
        (C.size_t)(len(blobs)),
        &settings)
    return proof, ret
}

/*
VerifyAggregateKzgProof is the binding for:
    C_KZG_RET verify_aggregate_kzg_proof(
        bool *out,
        const Blob blobs[],
        const KZGCommitment expected_kzg_commitments[],
        size_t n,
        const KZGProof *kzg_aggregated_proof,
        const KZGSettings *s);
*/
func VerifyAggregateKzgProof(blobs []Blob, commitments []Commitment, proof Proof) (C.bool, C.C_KZG_RET) {
    if len(blobs) != len(commitments) {
        panic("len(blobs) != len(commitments)")
    }
    var result C.bool
    ret := C.verify_aggregate_kzg_proof(
        &result,
        (*C.Blob)(unsafe.Pointer(&blobs)),
        (*C.KZGCommitment)(unsafe.Pointer(&commitments)),
        (C.size_t)(len(blobs)),
        (*C.KZGProof)(unsafe.Pointer(&proof)),
        &settings)
    return result, ret
}

/*
BlobToKzgCommitment is the binding for:
    C_KZG_RET blob_to_kzg_commitment(
        KZGCommitment *out,
        const Blob blob,
        const KZGSettings *s);
*/
func BlobToKzgCommitment(blob Blob) (C.KZGCommitment, C.C_KZG_RET) {
    commitment := C.KZGCommitment{}
    ret := C.blob_to_kzg_commitment(
        &commitment,
        (*C.uint8_t)(unsafe.Pointer(&blob)),
        &settings)
    return commitment, ret
}

/*
VerifyKzgProof is the binding for:
    C_KZG_RET verify_kzg_proof(
        bool *out,
        const KZGCommitment *polynomial_kzg,
        const uint8_t z[BYTES_PER_FIELD_ELEMENT],
        const uint8_t y[BYTES_PER_FIELD_ELEMENT],
        const KZGProof *kzg_proof,
        const KZGSettings *s);
*/
func VerifyKzgProof(commitment Commitment, z, y [bytesPerFieldElement]byte, proof Proof) (C.bool, C.C_KZG_RET) {
    var result C.bool
    ret := C.verify_kzg_proof(
        &result,
        (*C.KZGCommitment)(unsafe.Pointer(&commitment)),
        (*C.uint8_t)(unsafe.Pointer(&z)),
        (*C.uint8_t)(unsafe.Pointer(&y)),
        (*C.KZGProof)(unsafe.Pointer(&proof)),
        &settings)
    return result, ret
}
