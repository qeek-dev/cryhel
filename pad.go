package cryhel

import (
	"bytes"
	"unicode"
)

type Padding interface {
	Pad(in []byte, blockSize int) []byte
	UnPad(origData []byte) []byte
}

type zeroPadding struct{}

func (z zeroPadding) Pad(in []byte, blockSize int) []byte {
	padding := blockSize - len(in)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(in, padtext...)
}

func (z zeroPadding) UnPad(origData []byte) []byte {
	return bytes.TrimFunc(origData, func(r rune) bool {
		return r == rune(0)
	})
}

func NewZeroPadding() Padding {
	return zeroPadding{}
}

type spacePadding struct{}

func (s spacePadding) Pad(in []byte, blockSize int) []byte {
	padding := blockSize - len(in)%blockSize
	padtext := bytes.Repeat([]byte(" "), padding)
	return append(in, padtext...)
}

func (s spacePadding) UnPad(origData []byte) []byte {
	return bytes.TrimFunc(origData, unicode.IsSpace)
}

func NewSpacePadding() Padding {
	return spacePadding{}
}
