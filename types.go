package fuzz

import (
	gokzg "github.com/protolambda/go-kzg/eth"
)

type GoKzgBlobImpl []byte

func (b GoKzgBlobImpl) Len() int {
	return 4096
}

func (b GoKzgBlobImpl) At(index int) [32]byte {
	var blob [32]byte
	copy(blob[:], b[index*32:(index+1)*32])
	return blob
}

type GoKzgBlobSequenceImpl []GoKzgBlobImpl

func (b GoKzgBlobSequenceImpl) Len() int {
	return len(b)
}

func (b GoKzgBlobSequenceImpl) At(index int) gokzg.Blob {
	return b[index]
}
