[![CircleCI](https://circleci.com/gh/qeek-dev/cryhel.svg?style=svg)](https://circleci.com/gh/qeek-dev/cryhel)

# Qeek.dev crypto helper

> crypto helper to handle data encrypt and decrypt

## Environment

- [x] go 1.7.1 docker image: qeekdev/golang:1.7.1-ubuntu build from : tools/docker/golang
- [x] glide 0.12.1

## Installation

### clone repo and install go packages

```sh
# make github.com/qeek-dev if does not exist and switch to
$ cd $GOPATH/src/github.com/qeek-dev

# clone repo
$ git clone git@github.com:qeek-dev/cryhel.git

$ cd cryhel

# install requirement go packages
$ glide update
$ glide i
```

### Testing

```sh
$ go test
OK: 8 passed
PASS
ok      github.com/qeek-dev/cryhel      0.010s
```

## Usage

```go
// new crypto helper
c, err = cryhel.NewCrypto("AES256Key-32Characters1234567890")

// encrypt
enc, err := c.Encrypt.Msg("string your want to encrypt").Do()
enc, err := c.Encrypt.QueryEscapeMsg("string your want to encrypt").Do()

// decrypt
// Out(&out): json.Unmarshal to struct, dependency on what struct you encrypt to
dec, err := c.Decrypt.Msg("encrypt string").Do()
dec, err := c.Decrypt.Msg("encrypt string").Out(&out)
dec, err := c.Decrypt.QueryEscapeMsg("encryptBase64String").Do()
dec, err := c.Decrypt.QueryEscapeMsg("encryptBase64String").Out(&out)
```
