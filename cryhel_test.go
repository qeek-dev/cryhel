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
	if encryptString, err := s.c.Encrypt.Msg(sourceString).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		chk.Logf("encrypt base64 encode string: %q", encryptString)
	}
}

func (s *MySuite) Test_Decrypt_Base64_StdEncoding(chk *C) {
	encryptString := "cLcbvk4rpVRTj1kvu5pOi7ktZiCezDWcm8VR1f+XpP12eie0/cI6lagGcWXRMt8a"
	if creds, err := s.c.Decrypt.Msg(encryptString).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		if creds != "1/fFAGRNJru1FTz70BzhT3Zg" {
			chk.Errorf("got access_token %q expected %q", creds, "1/fFAGRNJru1FTz70BzhT3Zg")
		} else {
			chk.Logf("decrypt string: %q", creds)
		}
	}
}

func (s *MySuite) Test_Encrypt_Base64_RawURLEncoding(chk *C) {
	sourceString := "1/fFAGRNJru1FTz70BzhT3Zg"
	if encryptString, err := s.c.Encrypt.Msg(sourceString).Encoding(base64.RawURLEncoding).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		chk.Logf("encrypt base64 encode string: %q", encryptString)
	}
}

func (s *MySuite) Test_Decrypt_Base64_RawURLEncoding(chk *C) {
	encryptString := "yMeF0f/D03Hw2AieRkLejswAO0E36iO/KTph7R8uBKcWdiOC1MgWAqRwqBpVxpK/"
	if encryptString, err := s.c.Encrypt.Msg(encryptString).Encoding(base64.RawURLEncoding).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		chk.Logf("source string: %q", encryptString)
	}
}

func (s *MySuite) Test_Encrypt_Decrypt_Base64_RawURLEncoding(chk *C) {
	sourceString := "1/fFAGRNJru1FTz70BzhT3Zg"
	if encryptString, err := s.c.Encrypt.Msg(sourceString).Encoding(base64.RawURLEncoding).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		chk.Logf("encrypt base64 RawURLEncoding string: %q", encryptString)

		decryptString, err := s.c.Decrypt.Msg(encryptString).Encoding(base64.RawURLEncoding).Do()
		if err != nil {
			chk.Errorf("got decrypt message %q expected %q", decryptString, "1/fFAGRNJru1FTz70BzhT3Zg")
		} else {
			chk.Logf("decrypt decrypt message: %q", decryptString)
		}
	}
}

func (s *MySuite) Test_Encrypt_Decrypt_Msg(chk *C) {
	sourceString := `{"user":"admin","type":"2","streamKey":"live?token=b31d0e541427f52debea0f6d0ca368454f5323b384571b466f5894a3e100dd5d94cfb4a49ded"}`

	if encryptBase64String, err := s.c.Encrypt.Msg(sourceString).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		if decryptString, err := s.c.Decrypt.Msg(encryptBase64String).Do(); err != nil {
			chk.Errorf("got descrypt %q expected %q", decryptString, sourceString)
		} else {
			chk.Logf("decrypt base64 encode string: %q", decryptString)
		}
	}
}

func (s *MySuite) Test_Encrypt_Decrypt_Out_Msg(chk *C) {
	type Info struct {
		User      string `json:"user"`
		Type      string `json:"type"`
		StreamKey string `json:"streamKey"`
	}

	sourceString := `{"user":"admin","type":"2","streamKey":"live?token=b31d0e541427f52debea0f6d0ca368454f5323b384571b466f5894a3e100dd5d94cfb4a49ded"}`

	if encryptBase64String, err := s.c.Encrypt.Msg(sourceString).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		var b Info
		if err := s.c.Decrypt.Msg(encryptBase64String).Out(&b); err != nil {
			chk.Errorf("got descrypt %v expected %q", b, sourceString)
		} else {
			chk.Logf("decrypt base64 encode struct: %v", b)
		}
	}
}

func (s *MySuite) Test_Encrypt_Decrypt_Msg_Custom_Base64_Encoding(chk *C) {
	sourceString := `{"user":"admin","type":"2","streamKey":"live?token=b31d0e541427f52debea0f6d0ca368454f5323b384571b466f5894a3e100dd5d94cfb4a49ded"}`

	if encryptBase64String, err := s.c.Encrypt.Msg(sourceString).Encoding(base64.RawURLEncoding).Do(); err != nil {
		chk.Error(err.Error())
	} else {
		if decryptString, err := s.c.Decrypt.Msg(encryptBase64String).Encoding(base64.RawURLEncoding).Do(); err != nil {
			chk.Errorf("got descrypt %q expected %q", decryptString, sourceString)
		} else {
			chk.Logf("decrypt base64 encode string: %q", decryptString)
		}
	}
}
