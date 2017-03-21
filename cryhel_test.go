package cryhel_test

import (
	"encoding/base64"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/qeek-dev/cryhel"
)

func Test(t *testing.T) { TestingT(t) }

type MySuite struct {
	c *cryhel.Crypto
}

func (s *MySuite) SetUpTest(c *C) {
	s.c, _ = cryhel.NewCrypto("AES256Key-32Characters1234567890")
}

var _ = Suite(&MySuite{})

func (s *MySuite) Test_Encrypt_Base64_StdEncoding(chk *C) {
	sourceString := "1/fFAGRNJru1FTz70BzhT3Zg"

	encryptString, err := s.c.Encrypt.Msg(sourceString).Do()
	chk.Assert(err, IsNil)
	chk.Logf("encrypt base64 encode string: %q", encryptString)
}

func (s *MySuite) Test_Decrypt_Base64_StdEncoding(chk *C) {
	encryptString := "Ive8q7ljYMKl5cjrUBtUTDRs3oV0D8bxIKOP+wpuqqUZoflYYQgsGH0oIOLv77jP"

	creds, err := s.c.Decrypt.Msg(encryptString).Do()
	chk.Assert(err, IsNil)
	chk.Assert(creds, Equals, "1/fFAGRNJru1FTz70BzhT3Zg")
}

func (s *MySuite) Test_Encrypt_Base64_RawURLEncoding(chk *C) {
	sourceString := "1/fFAGRNJru1FTz70BzhT3Zg"

	encryptString, err := s.c.Encrypt.Msg(sourceString).Encoding(base64.RawURLEncoding).Do()
	chk.Assert(err, IsNil)
	chk.Logf("encrypt base64 encode string: %q", encryptString)
}

func (s *MySuite) Test_Decrypt_Base64_RawURLEncoding(chk *C) {
	encryptString := "Dva6D-FdXXK3tJs-0sIQaB73aSVUWsGHakeUA1GiCJOcsXDfhteRKYbFGKThiQgs"

	sourceString, err := s.c.Decrypt.Msg(encryptString).Encoding(base64.RawURLEncoding).Do()
	chk.Assert(err, IsNil)
	chk.Assert(sourceString, Equals, "1/fFAGRNJru1FTz70BzhT3Zg")
}

func (s *MySuite) Test_Encrypt_Decrypt_Base64_RawURLEncoding(chk *C) {
	sourceString := "1/fFAGRNJru1FTz70BzhT3Zg"

	encryptString, err := s.c.Encrypt.Msg(sourceString).Encoding(base64.RawURLEncoding).Do()
	chk.Assert(err, IsNil)
	chk.Logf("encrypt base64 RawURLEncoding string: %q", encryptString)

	decryptString, err := s.c.Decrypt.Msg(encryptString).Encoding(base64.RawURLEncoding).Do()
	chk.Assert(err, IsNil)
	chk.Assert(decryptString, Equals, sourceString)
}

func (s *MySuite) Test_Encrypt_Decrypt_Msg(chk *C) {
	sourceString := `{"user":"admin","type":"2","streamKey":"live?token=b31d0e541427f52debea0f6d0ca368454f5323b384571b466f5894a3e100dd5d94cfb4a49ded"}`

	encryptBase64String, err := s.c.Encrypt.Msg(sourceString).Do()
	chk.Assert(err, IsNil)
	decryptString, err := s.c.Decrypt.Msg(encryptBase64String).Do()
	chk.Assert(decryptString, Equals, sourceString)
}

func (s *MySuite) Test_Encrypt_Decrypt_Out_Msg(chk *C) {
	type Info struct {
		User      string `json:"user"`
		Type      string `json:"type"`
		StreamKey string `json:"streamKey"`
	}

	sourceString := `{"user":"admin","type":"2","streamKey":"live?token=b31d0e541427f52debea0f6d0ca368454f5323b384571b466f5894a3e100dd5d94cfb4a49ded"}`
	encryptBase64String, err := s.c.Encrypt.Msg(sourceString).Do()
	chk.Assert(err, IsNil)

	var b Info
	err = s.c.Decrypt.Msg(encryptBase64String).Out(&b)
	chk.Assert(err, IsNil)
	chk.Assert(b.User, Equals, "admin")
}

func (s *MySuite) Test_Encrypt_Decrypt_Msg_Custom_Base64_Encoding(chk *C) {
	sourceString := `{"user":"admin","type":"2","streamKey":"live?token=b31d0e541427f52debea0f6d0ca368454f5323b384571b466f5894a3e100dd5d94cfb4a49ded"}`

	encryptBase64String, err := s.c.Encrypt.Msg(sourceString).Encoding(base64.RawURLEncoding).Do()
	chk.Assert(err, IsNil)
	decryptString, err := s.c.Decrypt.Msg(encryptBase64String).Encoding(base64.RawURLEncoding).Do()
	chk.Assert(err, IsNil)
	chk.Assert(decryptString, Equals, sourceString)
}

func (s *MySuite) Test_Mobile_Team_Decrypt(chk *C) {
	encryptString := "tZMQaHpwtCcHoymwJ9kUQLW3OMzS6sfqm9LZTkwGLsBrqdqhCAMrgYtnAV5tlkBuZLU4WRWg96Lwbq0bkAcs0WgbdroFtLie9lu//pHzVvxHkqIgZT6qL1wGggd9fE+mJESOGVYwv1ct9oJRE3h1UFuSHPK24EFoYauKIIE2ts3LPpha+8lNpXeuDAzpWQDDzS3la9ic1UE1WhZEsZIoRiHZbA7XdyaSOKVrSc/Z58Ql8ArsLCqpkRnt8WRGMoNTCms2pT6a6qCTNNQ03P3M27AdjBiQPsOGSzZa/g7lNo59lIQnxEXWq9UgU8Jh/ub0zg8glzOY/v3QqJjaubHHUMtE6jolK/yYowWglJ6iWN8="

	encryptString, err := s.c.Decrypt.Msg(encryptString).Do()
	chk.Assert(err, IsNil)
	chk.Logf("encrypt base64 encode string: %q", encryptString)
}

func (s *MySuite) Test_Mobile_Team_Decrypt2(chk *C) {
	type Credentials struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Provider     string `json:"provider"`
		Error        string `json:"error"`
		Scope        string `json:"scope"`
	}

	encryptString := "tZMQaHpwtCcHoymwJ9kUQLW3OMzS6sfqm9LZTkwGLsBrqdqhCAMrgYtnAV5tlkBuZLU4WRWg96Lwbq0bkAcs0WgbdroFtLie9lu//pHzVvxHkqIgZT6qL1wGggd9fE+mJESOGVYwv1ct9oJRE3h1UFuSHPK24EFoYauKIIE2ts3LPpha+8lNpXeuDAzpWQDDzS3la9ic1UE1WhZEsZIoRiHZbA7XdyaSOKVrSc/Z58Ql8ArsLCqpkRnt8WRGMoNTCms2pT6a6qCTNNQ03P3M27AdjBiQPsOGSzZa/g7lNo59lIQnxEXWq9UgU8Jh/ub0zg8glzOY/v3QqJjaubHHUMtE6jolK/yYowWglJ6iWN8="

	var creds Credentials
	err := s.c.Decrypt.Msg(encryptString).Out(&creds)
	chk.Assert(err, IsNil)
	chk.Assert(creds.Provider, Equals, "google")
}
