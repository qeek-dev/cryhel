package cryhel_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/qeek-dev/cryhel"
	"github.com/stretchr/testify/assert"
)

const secretKey = "AES256Key-32Characters1234567890"

type setupSubTest func(t *testing.T) func(t *testing.T)

type cryhelTestSuit struct {
	crypto *cryhel.Crypto
}

func (c *cryhelTestSuit) SetupSubTest(_ *testing.T) func(t *testing.T) {
	return func(t *testing.T) {

	}
}

func setupCryhelTestSuit(t *testing.T) (cryhelTestSuit, func(t *testing.T)) {
	s := cryhelTestSuit{}
	return s, func(t *testing.T) {

	}
}

func Test_Encrypt(t *testing.T) {
	s, teardownTestCase := setupCryhelTestSuit(t)
	defer teardownTestCase(t)

	zcrypto, _ := cryhel.NewCryptoWithPadding(secretKey, cryhel.NewZeroPadding())
	scrypto, _ := cryhel.NewCryptoWithPadding(secretKey, cryhel.NewSpacePadding())

	tt := []struct {
		desc               string
		giveBase64Encoding *base64.Encoding
		giveMsg            string
		setupSubTest       setupSubTest
	}{
		{
			desc:               "zeropadding encrypt StdEncoding",
			giveBase64Encoding: base64.StdEncoding,
			giveMsg:            "",
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = zcrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "zeropadding encrypt RawURLEncoding",
			giveBase64Encoding: base64.RawURLEncoding,
			giveMsg:            "",
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = zcrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "spacepadding encrypt StdEncoding",
			giveBase64Encoding: base64.StdEncoding,
			giveMsg:            "",
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = scrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "spacepadding encrypt RawURLEncoding",
			giveBase64Encoding: base64.RawURLEncoding,
			giveMsg:            "",
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = scrypto
				return func(t *testing.T) {

				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			teardownSubTest := tc.setupSubTest(t)
			defer teardownSubTest(t)

			_, err := s.crypto.Encrypt.Msg(tc.giveMsg).Encoding(tc.giveBase64Encoding).Do()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		})
	}
}

func Test_Decrypt(t *testing.T) {
	s, teardownTestCase := setupCryhelTestSuit(t)
	defer teardownTestCase(t)

	zcrypto, _ := cryhel.NewCryptoWithPadding(secretKey, cryhel.NewZeroPadding())
	scrypto, _ := cryhel.NewCryptoWithPadding(secretKey, cryhel.NewSpacePadding())

	tt := []struct {
		desc               string
		giveBase64Encoding *base64.Encoding
		giveMsg            string
		setupSubTest       setupSubTest
	}{
		{
			desc:               "zeropadding decrypt StdEncoding",
			giveBase64Encoding: base64.StdEncoding,
			giveMsg: func() string {
				enc, _ := zcrypto.Encrypt.Msg("mock string").Encoding(base64.StdEncoding).Do()
				return enc
			}(),
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = zcrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "zeropadding decrypt RawURLEncoding",
			giveBase64Encoding: base64.RawURLEncoding,
			giveMsg: func() string {
				enc, _ := zcrypto.Encrypt.Msg("mock string").Encoding(base64.RawURLEncoding).Do()
				return enc
			}(),
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = zcrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "spacepadding decrypt StdEncoding",
			giveBase64Encoding: base64.StdEncoding,
			giveMsg: func() string {
				enc, _ := scrypto.Encrypt.Msg("mock string").Encoding(base64.StdEncoding).Do()
				return enc
			}(),
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = scrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "spacepadding decrypt RawURLEncoding",
			giveBase64Encoding: base64.RawURLEncoding,
			giveMsg: func() string {
				enc, _ := scrypto.Encrypt.Msg("mock string").Encoding(base64.RawURLEncoding).Do()
				return enc
			}(),
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = scrypto
				return func(t *testing.T) {

				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			teardownSubTest := tc.setupSubTest(t)
			defer teardownSubTest(t)

			_, err := s.crypto.Decrypt.Msg(tc.giveMsg).Encoding(tc.giveBase64Encoding).Do()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		})
	}
}

func Test_Decrypt_Out(t *testing.T) {
	s, teardownTestCase := setupCryhelTestSuit(t)
	defer teardownTestCase(t)

	zcrypto, _ := cryhel.NewCryptoWithPadding(secretKey, cryhel.NewZeroPadding())
	scrypto, _ := cryhel.NewCryptoWithPadding(secretKey, cryhel.NewSpacePadding())

	type Info struct {
		User      string `json:"user"`
		Type      string `json:"type"`
		StreamKey string `json:"streamKey"`
	}

	Info2String := func(i Info) string {
		s, _ := json.Marshal(i)
		return string(s)
	}

	info := Info{
		User:      "admin",
		Type:      "2",
		StreamKey: "live?token=b31d0e541427f52debea0f6d0ca368454f5323b384571b466f5894a3e100dd5d94cfb4a49ded",
	}

	tt := []struct {
		desc               string
		giveBase64Encoding *base64.Encoding
		giveMsg            string
		wantOut            Info
		setupSubTest       setupSubTest
	}{
		{
			desc:               "zeropadding decrypt Out StdEncoding",
			giveBase64Encoding: base64.StdEncoding,
			giveMsg: func() string {
				enc, _ := zcrypto.Encrypt.Msg(Info2String(info)).Encoding(base64.StdEncoding).Do()
				return enc
			}(),
			wantOut: info,
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = zcrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "zeropadding decrypt Out RawURLEncoding",
			giveBase64Encoding: base64.RawURLEncoding,
			giveMsg: func() string {
				enc, _ := zcrypto.Encrypt.Msg(Info2String(info)).Encoding(base64.RawURLEncoding).Do()
				return enc
			}(),
			wantOut: info,
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = zcrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "spacepadding decrypt Out StdEncoding",
			giveBase64Encoding: base64.StdEncoding,
			giveMsg: func() string {
				enc, _ := scrypto.Encrypt.Msg(Info2String(info)).Encoding(base64.StdEncoding).Do()
				return enc
			}(),
			wantOut: info,
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = scrypto
				return func(t *testing.T) {

				}
			},
		},
		{
			desc:               "spacepadding decrypt Out RawURLEncoding",
			giveBase64Encoding: base64.RawURLEncoding,
			giveMsg: func() string {
				enc, _ := scrypto.Encrypt.Msg(Info2String(info)).Encoding(base64.RawURLEncoding).Do()
				return enc
			}(),
			wantOut: info,
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = scrypto
				return func(t *testing.T) {

				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			teardownSubTest := tc.setupSubTest(t)
			defer teardownSubTest(t)

			err := s.crypto.Decrypt.Msg(tc.giveMsg).Encoding(tc.giveBase64Encoding).Out(&tc.wantOut)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, info, tc.wantOut, fmt.Sprintf("%s: expected res %v got %v", tc.desc, info, tc.wantOut))
		})
	}
}

func Test_QcloudConnector_Decrypt(t *testing.T) {
	s, teardownTestCase := setupCryhelTestSuit(t)
	defer teardownTestCase(t)

	scrypto, _ := cryhel.NewCryptoWithPadding("H9SGAp2dxB4vetVJ9QeE3svzlpvVJYZA", cryhel.NewSpacePadding())

	type Credentials struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Provider     string `json:"provider"`
		Error        string `json:"error"`
		Scope        string `json:"scope"`
	}

	tt := []struct {
		desc         string
		givenEnc     string
		wantOut      Credentials
		setupSubTest setupSubTest
	}{
		{
			desc:     "decrypt qcloud connector",
			givenEnc: "m7GFaaaHklwy0rGyRCjrk11viXiyrYZ0OR32L/xaVKHE2FlmM9lij7Z7qYfLqRiRT2nKCKtJYbf8IiLq9pYNt7WuGuShwhufFNNavM4JIss4cUvoggIHPT+XDcRE1KVcEuAOS0ksXy2V2QAcCegGJ6ibV7g6LIZE+QWMorp6lNZM7r2TFC1ZvHJXtnU+AJOzTvvKw24iMNbtZp0WlPF4VPFIELH3Tu8uFbU64f024NrPHFFGvCpsaVbZDKOgS8GEWY1ns3fyX9mO/HXZKt5YyTzrLqyS9moejPaAw+G5zCfWDWjEheOvzUdQcc7a9RZk2wFxbh35C4MMs/OUmxxW+sqQjYZqlXkyqUbtXxkePSffvAr+vBQ+62cvzc6XYAsK+8X2yGQxKpgDFkw1U4QF9zR2s7+TwRB0z1DPD1ofCOHqfu8VEvPiTcQtLoo7Y78kkghjS1rmK9UrChhpZkmRSw==",
			setupSubTest: func(t *testing.T) func(t *testing.T) {
				s.crypto = scrypto
				return func(t *testing.T) {

				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			teardownSubTest := tc.setupSubTest(t)
			defer teardownSubTest(t)

			err := s.crypto.Decrypt.Msg(tc.givenEnc).Out(&tc.wantOut)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.NotEmpty(t, tc.wantOut)
		})
	}
}
