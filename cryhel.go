package cryhel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
)

// any is purely semantic
type any interface{}

// Pointer is purely semantic
type pointer interface{}

func isPointer(value any) bool {
	if reflect.ValueOf(value).Kind() != reflect.Ptr {
		return false
	}
	return true
}

// encrypt general func
func (c *Crypto) encrypt(msg string) ([]byte, error) {
	plaintext := SpacePadding([]byte(msg), c.block.BlockSize())

	if len(plaintext)%c.block.BlockSize() != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, c.block.BlockSize()+len(plaintext))
	iv := ciphertext[:c.block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New(err.Error())
	}

	mode := cipher.NewCBCEncrypter(c.block, iv)
	mode.CryptBlocks(ciphertext[c.block.BlockSize():], plaintext)

	return ciphertext, nil
}

// decrypt general func
func (c *Crypto) decrypt(ciphertext []byte) ([]byte, error) {
	blockMode := cipher.NewCBCDecrypter(c.block, c.bkey[:c.block.BlockSize()])
	if len(ciphertext) < c.block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}
	if len(ciphertext)%c.block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	planeText := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(planeText, ciphertext)

	planeText = SpaceUnPadding(planeText[c.block.BlockSize():])
	return []byte(strings.TrimSpace(string(planeText))), nil
}

func SpacePadding(in []byte, blockSize int) []byte {
	padding := blockSize - len(in)%blockSize
	padtext := bytes.Repeat([]byte(" "), padding)
	return append(in, padtext...)
}

func SpaceUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData, unicode.IsSpace)
}

// Crypto struct
type Crypto struct {
	block cipher.Block
	bkey  []byte

	Encrypt *EncryptService
	Decrypt *DecryptService
}

func NewCrypto(secretkey string) (c *Crypto, err error) {
	if secretkey == "" {
		err = errors.New("secret key empty")
		return
	}

	c = &Crypto{}
	c.bkey = []byte(secretkey)
	c.block, err = aes.NewCipher(c.bkey)
	c.Encrypt = NewEncryptService(c)
	c.Decrypt = NewDecryptService(c)
	if err != nil {
		return
	}
	return
}

//-----------------------------------------------------------------------------
// EncryptService
type EncryptService struct {
	s *Crypto
}

func NewEncryptService(s *Crypto) *EncryptService {
	rs := &EncryptService{s: s}
	return rs
}

// method  "Crypto.Encrypt.Msg"
type EncryptMsgCall struct {
	s *Crypto
	e *base64.Encoding
	m string
}

func (r *EncryptService) Msg(msg string) *EncryptMsgCall {
	c := &EncryptMsgCall{s: r.s, m: msg, e: base64.StdEncoding}
	return c
}

func (r *EncryptMsgCall) Encoding(encoding *base64.Encoding) *EncryptMsgCall {
	r.e = encoding
	return r
}

func (r *EncryptMsgCall) Do() (string, error) {
	if ciphertext, err := r.s.encrypt(r.m); err != nil {
		return "", err
	} else {
		return r.e.EncodeToString(ciphertext), nil
	}
}

//-----------------------------------------------------------------------------
// DecryptService
type DecryptService struct {
	s *Crypto
}

func NewDecryptService(s *Crypto) *DecryptService {
	rs := &DecryptService{s: s}
	return rs
}

// method  "Crypto.Decrypt.Msg"
type DecryptMsgCall struct {
	s *Crypto
	e *base64.Encoding
	m string
}

func (r *DecryptService) Msg(msg string) *DecryptMsgCall {
	c := &DecryptMsgCall{s: r.s, m: msg, e: base64.StdEncoding}
	return c
}

func (r *DecryptMsgCall) Encoding(encoding *base64.Encoding) *DecryptMsgCall {
	r.e = encoding
	return r
}

func (r *DecryptMsgCall) Do() (string, error) {
	ciphertext, _ := r.e.DecodeString(r.m) // decrypt base64
	buf, err := r.s.decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

func (r *DecryptMsgCall) Out(out pointer) error {
	if !isPointer(out) {
		return errors.New(fmt.Sprintf("Value '%s' is not a pointer", out))
	}

	ciphertext, _ := r.e.DecodeString(r.m) // decrypt base64
	buf, err := r.s.decrypt(ciphertext)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(buf, out); err != nil {
		return err
	} else {
		return nil
	}
}

//-----------------------------------------------------------------------------
