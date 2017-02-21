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

### glide install error handling
If you get error message
```
...
[INFO]     Preparing to install 1 package.
[INFO]     Attempting to get package gopkg.in/check.v1
[INFO]     --> Moving gopkg.in/check.v1 from testImport to import
[INFO]     Downloading dependencies. Please wait...
[INFO]     --> Fetching gopkg.in/check.v1.
[WARN]     Unable to checkout gopkg.in/check.v1
[ERROR]     Update failed for gopkg.in/check.v1: Unable to get repository
[ERROR]     Failed to checkout packages: Unable to get repository
...
```
you need settting your git config
```sh
$ git config --global http.followRedirects true
```
ref: http://qiita.com/jiskanulo/items/49197cbdcc544a7f02ab

### Testing

```sh
$ go test
OK: 7 passed
PASS
ok      github.com/qeek-dev/cryhel      0.010s
```

## Usage

install via glide

```sh
$ glide get github.com/qeek-dev/cryhel
```

```go
// new crypto helper
c, err = cryhel.NewCrypto("AES256Key-32Characters1234567890")

// encrypt (default base64 StdEncoding)
enc, err := c.Encrypt.Msg("string your want to encrypt").Do()

// Encrypt parameter support
// - StdEncoding
// - URLEncoding
// - RawStdEncoding
// - RawURLEncoding
enc, err := c.Encrypt.Msg("string your want to encrypt").Encoding(base64.RawURLEncoding).Do()

// decrypt with default encoding: base64.StdEncoding
dec, err := c.Decrypt.Msg("encrypt string").Do()

// Out(&out): json.Unmarshal to struct, dependency on what struct you encrypt to
// decrypt with default encoding: base64.StdEncoding
dec, err := c.Decrypt.Msg("encrypt string").Do(&out)

// Out(&out): json.Unmarshal to struct, dependency on what struct you encrypt to
// decrypt with default encoding: base64.RawURLEncoding
dec, err := c.Decrypt.Msg("encryptBase64String").Encoding(base64.RawURLEncoding).Do(&out)
```
