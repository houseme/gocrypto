// Copyright 2019 go-crypto Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/houseme/gocrypto"
)

type RSACryptTest struct {
	data       string
	encodeType gocrypto.Encode
	hashType   gocrypto.Hash
}

func TestRSACrypt(t *testing.T) {
	var secretInfo = SecretInfo{
		PublicKey:          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyoiAraTnAbCoqGVOKugFDM2/ms2szXmb3zTOU3ByicH/XPZqy7Eougbs8OQQIoNW4xKw8PNyWf0lfr90qBfPj27INn6N7umVmbHCNCKkQ4frPn46xesw1ywtc2GhOEzZlC8ajlnzBUkj5FJZcrNjXfFmfsQcFQP0g/o/3CAUpk1BXFXt7eZsaYdyn0m7fMoyFt1wlF8egQeGYYE98vtKsvrII51HK8vOEf+5VXU4UZxGfvyzS3A8kuNEkKEh1n9mazjfPBT0KGSiOGh7Nugks+jjfswSgXRK/b2eP3fS7U625rbS798pKxnoS2E0Pgpzdk5fWoNgAlG/n2F9oI2/kQIDAQAB",
		PublicKeyDataType:  gocrypto.Base64,
		PrivateKey:         "MIIEowIBAAKCAQEAyoiAraTnAbCoqGVOKugFDM2/ms2szXmb3zTOU3ByicH/XPZqy7Eougbs8OQQIoNW4xKw8PNyWf0lfr90qBfPj27INn6N7umVmbHCNCKkQ4frPn46xesw1ywtc2GhOEzZlC8ajlnzBUkj5FJZcrNjXfFmfsQcFQP0g/o/3CAUpk1BXFXt7eZsaYdyn0m7fMoyFt1wlF8egQeGYYE98vtKsvrII51HK8vOEf+5VXU4UZxGfvyzS3A8kuNEkKEh1n9mazjfPBT0KGSiOGh7Nugks+jjfswSgXRK/b2eP3fS7U625rbS798pKxnoS2E0Pgpzdk5fWoNgAlG/n2F9oI2/kQIDAQABAoIBAF378hqiR0CVhe5+9EMc4BsM7zka8HF5WUe+7W/y4nPivmmZP/29/DQ3OoSekI4zfIJrDgkCL7JqspeaqLvIMN1Sfz4qhBq18mIcBw7CdI+R5yxcz1FAzq1LJtxAFdxWbTFCmoQsYYW2Zx1wyWlcrWPOvc1dm9p0t2b3HeM8T9jLdY+D0Bm9zmAS0nwTuDBxYS77DB9Ncl6pWLLd197/5IoN1/nunFuzpkiwMPI9RF7lgrnUthc/1Gfnylz5/tXCiQsEVSbAdbMXt9nsV0RgVeMcPq/aUqTMLS2lIV8JySWDrRQi4yPHU0hIjcp6ggo53YMuncJZweI/wwkJexojz0ECgYEA5QzRObpU0CryfJ7qa97/USIKHbvl6PuQG9OLyUeP9bG0edidQhUrR4EZwjIl73O8CTJ0bB24wAKZZEOK3eJeqG/N0q+CiD83ygr8pSZzpE1xvqQp32IgXtgvm7/UmT8cfAp05Z3bF4jcA8uXwodBz4NsVGijlO78PsCooLsArM0CgYEA4lz5pXDEN3w5JwkbspLnUSUS738hne8YM0PchCaww+8sXLS9GLL2CHcvwh6Tv9Mee7r6SdbDI73x118y68WEDDhidiYZCLhXJN2v12ezJOMqH5m9wVJzQOGNv6kPV1EW1WlWxoJQGxCdzbZMLxtTbyTZe3+iAVG++8u6NWMV3dUCgYA1dm1rnQto321kGy+6Z/2OMXTNBeufGwDDDfilzZdTkNwASMhEAW7trLuXcV8bahcsymMUTUevQawOFBnYupq/lAEluSOtq5vZBAF+huAdLJptFiJT6rKFkM5j+z2jW3DJnyMz6UmXT7GTDTVqCWoaBqIFfbsY60NjXlK92YhJzQKBgQDWfQjktbSHasLw9RV0oPRklD+cBhfBgfOpZ+0En3CxR+j+MxhW1gSBQwZS5wxTIGXrEeHlo4UmUe5diExE0dRsi+ToVPM1qw6P1SuwbQd3tXSNmu0NyOWCnfblm/j4YNLFB1p9IK9s5dLRQKJxpG/ribw15FuK6n2QM5vOyIPIvQKBgE5PUzRUCCVsjKAxZOfaZQatMbSzAUSB3bNmUw+F3pDq8ibs6XXvtySowG2femlPDNL7mDMuUc9kYrtTFTQNrEsQGB55wBopX3UxzRjpXJoAQ/d+RPdrSJC7xJyu+URoFI6ae0I3bx1BzjctYU0Rv5DUh+j9leMH5N2S9vHb+vqu",
		PrivateKeyType:     gocrypto.PKCS1,
		PrivateKeyDataType: gocrypto.Base64,
		HashType:           gocrypto.SHA256,
	}
	handle := NewRSACrypt(secretInfo)
	var rsaTests = []RSACryptTest{
		{
			"test",
			gocrypto.HEX,
			gocrypto.MD5,
		},
		{
			"base64",
			gocrypto.Base64,
			gocrypto.SHA256,
		},
		{
			"01234567890123456789012345678901234567890123456789012",
			gocrypto.String,
			gocrypto.SHA1,
		},
	}
	for _, rsaTest := range rsaTests {
		// encrypt data & encode result
		encrypt, err := handle.Encrypt(rsaTest.data, rsaTest.encodeType)
		if err != nil {
			t.Fatalf("encrypt error : %v", err)
		}
		// decrypt encrypted & encoded data
		decrypt, err := handle.Decrypt(encrypt, rsaTest.encodeType)
		if err != nil {
			t.Fatalf("decrypt error : %v", err)
		}
		if decrypt != rsaTest.data {
			t.Fatalf("decrypt get result %s , want get %s ", decrypt, rsaTest.data)
		}
		// sign data with digest algorithm & encode result
		handle.SetHashType(rsaTest.hashType)
		sign, err := handle.Sign(rsaTest.data, rsaTest.encodeType)
		if err != nil {
			t.Fatalf("sign error : %v", err)
		}
		// verify data that signed with digest algorithm & encoded whether match original data
		handle.SetHashType(rsaTest.hashType)
		verifySign, err := handle.VerifySign(rsaTest.data, sign, rsaTest.encodeType)
		if err != nil {
			t.Fatalf("verifySign error : %v", err)
		}
		if !verifySign {
			t.Fatal("verifySign result failed")
		}

		encrypt, err = handle.EncryptByPriKey(rsaTest.data, rsaTest.encodeType)
		if err != nil {
			t.Fatalf("encrypt error : %v", err)
		}
		decrypt, err = handle.DecryptByPublic(encrypt, rsaTest.encodeType)
		if err != nil {
			t.Fatalf("decrypt error : %v", err)
		}
		if decrypt != rsaTest.data {
			t.Fatalf("decrypt get result %s , want get %s ", decrypt, rsaTest.data)
		}
	}
}

func BenchmarkRSACrypt(t *testing.B) {
	for i := 0; i < t.N; i++ {
		var secretInfo = SecretInfo{
			PublicKey:          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyoiAraTnAbCoqGVOKugFDM2/ms2szXmb3zTOU3ByicH/XPZqy7Eougbs8OQQIoNW4xKw8PNyWf0lfr90qBfPj27INn6N7umVmbHCNCKkQ4frPn46xesw1ywtc2GhOEzZlC8ajlnzBUkj5FJZcrNjXfFmfsQcFQP0g/o/3CAUpk1BXFXt7eZsaYdyn0m7fMoyFt1wlF8egQeGYYE98vtKsvrII51HK8vOEf+5VXU4UZxGfvyzS3A8kuNEkKEh1n9mazjfPBT0KGSiOGh7Nugks+jjfswSgXRK/b2eP3fS7U625rbS798pKxnoS2E0Pgpzdk5fWoNgAlG/n2F9oI2/kQIDAQAB",
			PublicKeyDataType:  gocrypto.Base64,
			PrivateKey:         "MIIEowIBAAKCAQEAyoiAraTnAbCoqGVOKugFDM2/ms2szXmb3zTOU3ByicH/XPZqy7Eougbs8OQQIoNW4xKw8PNyWf0lfr90qBfPj27INn6N7umVmbHCNCKkQ4frPn46xesw1ywtc2GhOEzZlC8ajlnzBUkj5FJZcrNjXfFmfsQcFQP0g/o/3CAUpk1BXFXt7eZsaYdyn0m7fMoyFt1wlF8egQeGYYE98vtKsvrII51HK8vOEf+5VXU4UZxGfvyzS3A8kuNEkKEh1n9mazjfPBT0KGSiOGh7Nugks+jjfswSgXRK/b2eP3fS7U625rbS798pKxnoS2E0Pgpzdk5fWoNgAlG/n2F9oI2/kQIDAQABAoIBAF378hqiR0CVhe5+9EMc4BsM7zka8HF5WUe+7W/y4nPivmmZP/29/DQ3OoSekI4zfIJrDgkCL7JqspeaqLvIMN1Sfz4qhBq18mIcBw7CdI+R5yxcz1FAzq1LJtxAFdxWbTFCmoQsYYW2Zx1wyWlcrWPOvc1dm9p0t2b3HeM8T9jLdY+D0Bm9zmAS0nwTuDBxYS77DB9Ncl6pWLLd197/5IoN1/nunFuzpkiwMPI9RF7lgrnUthc/1Gfnylz5/tXCiQsEVSbAdbMXt9nsV0RgVeMcPq/aUqTMLS2lIV8JySWDrRQi4yPHU0hIjcp6ggo53YMuncJZweI/wwkJexojz0ECgYEA5QzRObpU0CryfJ7qa97/USIKHbvl6PuQG9OLyUeP9bG0edidQhUrR4EZwjIl73O8CTJ0bB24wAKZZEOK3eJeqG/N0q+CiD83ygr8pSZzpE1xvqQp32IgXtgvm7/UmT8cfAp05Z3bF4jcA8uXwodBz4NsVGijlO78PsCooLsArM0CgYEA4lz5pXDEN3w5JwkbspLnUSUS738hne8YM0PchCaww+8sXLS9GLL2CHcvwh6Tv9Mee7r6SdbDI73x118y68WEDDhidiYZCLhXJN2v12ezJOMqH5m9wVJzQOGNv6kPV1EW1WlWxoJQGxCdzbZMLxtTbyTZe3+iAVG++8u6NWMV3dUCgYA1dm1rnQto321kGy+6Z/2OMXTNBeufGwDDDfilzZdTkNwASMhEAW7trLuXcV8bahcsymMUTUevQawOFBnYupq/lAEluSOtq5vZBAF+huAdLJptFiJT6rKFkM5j+z2jW3DJnyMz6UmXT7GTDTVqCWoaBqIFfbsY60NjXlK92YhJzQKBgQDWfQjktbSHasLw9RV0oPRklD+cBhfBgfOpZ+0En3CxR+j+MxhW1gSBQwZS5wxTIGXrEeHlo4UmUe5diExE0dRsi+ToVPM1qw6P1SuwbQd3tXSNmu0NyOWCnfblm/j4YNLFB1p9IK9s5dLRQKJxpG/ribw15FuK6n2QM5vOyIPIvQKBgE5PUzRUCCVsjKAxZOfaZQatMbSzAUSB3bNmUw+F3pDq8ibs6XXvtySowG2femlPDNL7mDMuUc9kYrtTFTQNrEsQGB55wBopX3UxzRjpXJoAQ/d+RPdrSJC7xJyu+URoFI6ae0I3bx1BzjctYU0Rv5DUh+j9leMH5N2S9vHb+vqu",
			PrivateKeyType:     gocrypto.PKCS1,
			PrivateKeyDataType: gocrypto.Base64,
			HashType:           gocrypto.SHA256,
		}
		handle := NewRSACrypt(secretInfo)
		var rsaTests = []RSACryptTest{
			{
				"test",
				gocrypto.HEX,
				gocrypto.MD5,
			},
			{
				"base64",
				gocrypto.Base64,
				gocrypto.SHA256,
			},
			{
				"01234567890123456789012345678901234567890123456789012",
				gocrypto.String,
				gocrypto.SHA1,
			},
		}
		for _, rsaTest := range rsaTests {
			// encrypt data & encode result
			encrypt, err := handle.Encrypt(rsaTest.data, rsaTest.encodeType)
			if err != nil {
				t.Fatalf("encrypt error : %v", err)
			}
			// decrypt encrypted & encoded data
			decrypt, err := handle.Decrypt(encrypt, rsaTest.encodeType)
			if err != nil {
				t.Fatalf("decrypt error : %v", err)
			}
			if decrypt != rsaTest.data {
				t.Fatalf("decrypt get result %s , want get %s ", decrypt, rsaTest.data)
			}
			// sign data with digest algorithm & encode result
			handle.SetHashType(rsaTest.hashType)
			sign, err := handle.Sign(rsaTest.data, rsaTest.encodeType)
			if err != nil {
				t.Fatalf("sign error : %v", err)
			}
			// verify data that signed with digest algorithm & encoded whether match original data
			handle.SetHashType(rsaTest.hashType)
			verifySign, err := handle.VerifySign(rsaTest.data, sign, rsaTest.encodeType)
			if err != nil {
				t.Fatalf("verifySign error : %v", err)
			}
			if !verifySign {
				t.Fatal("verifySign result failed")
			}
			encrypt, err = handle.EncryptByPriKey(rsaTest.data, rsaTest.encodeType)
			if err != nil {
				t.Fatalf("encrypt error : %v", err)
			}
			decrypt, err = handle.DecryptByPublic(encrypt, rsaTest.encodeType)
			if err != nil {
				t.Fatalf("decrypt error : %v", err)
			}
			if decrypt != rsaTest.data {
				t.Fatalf("decrypt get result %s , want get %s ", decrypt, rsaTest.data)
			}
		}
	}
}

type testEncryptOAEPMessage struct {
	in   []byte
	seed []byte
	out  []byte
}

type testEncryptOAEPStruct struct {
	modulus string
	e       int
	d       string
	msgs    []testEncryptOAEPMessage
}

func TestEncryptDecryptOAEP(t *testing.T) {
	sha256 := sha256.New()
	n := new(big.Int)
	d := new(big.Int)
	for i, test := range testEncryptOAEPData {
		n.SetString(test.modulus, 16)
		d.SetString(test.d, 16)
		priv := new(rsa.PrivateKey)
		priv.PublicKey = rsa.PublicKey{N: n, E: test.e}
		priv.D = d

		for j, message := range test.msgs {
			label := []byte(fmt.Sprintf("hi#%d", j))
			enc, err := rsa.EncryptOAEP(sha256, rand.Reader, &priv.PublicKey, message.in, label)
			if err != nil {
				t.Errorf("#%d,%d: EncryptOAEP: %v", i, j, err)
				continue
			}
			dec, err := rsa.DecryptOAEP(sha256, rand.Reader, priv, enc, label)
			if err != nil {
				t.Errorf("#%d,%d: DecryptOAEP: %v", i, j, err)
				continue
			}
			if !bytes.Equal(dec, message.in) {
				t.Errorf("#%d,%d: round trip %q -> %q", i, j, message.in, dec)
			}
		}
	}
}

// testEncryptOAEPData contains a subset of the vectors from RSA's "Test vectors for RSA-OAEP".
var testEncryptOAEPData = []testEncryptOAEPStruct{
	// Key 1
	{"a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
		65537,
		"53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
		[]testEncryptOAEPMessage{
			// Example 1.1
			{
				[]byte{0x66, 0x28, 0x19, 0x4e, 0x12, 0x07, 0x3d, 0xb0,
					0x3b, 0xa9, 0x4c, 0xda, 0x9e, 0xf9, 0x53, 0x23, 0x97,
					0xd5, 0x0d, 0xba, 0x79, 0xb9, 0x87, 0x00, 0x4a, 0xfe,
					0xfe, 0x34,
				},
				[]byte{0x18, 0xb7, 0x76, 0xea, 0x21, 0x06, 0x9d, 0x69,
					0x77, 0x6a, 0x33, 0xe9, 0x6b, 0xad, 0x48, 0xe1, 0xdd,
					0xa0, 0xa5, 0xef,
				},
				[]byte{0x35, 0x4f, 0xe6, 0x7b, 0x4a, 0x12, 0x6d, 0x5d,
					0x35, 0xfe, 0x36, 0xc7, 0x77, 0x79, 0x1a, 0x3f, 0x7b,
					0xa1, 0x3d, 0xef, 0x48, 0x4e, 0x2d, 0x39, 0x08, 0xaf,
					0xf7, 0x22, 0xfa, 0xd4, 0x68, 0xfb, 0x21, 0x69, 0x6d,
					0xe9, 0x5d, 0x0b, 0xe9, 0x11, 0xc2, 0xd3, 0x17, 0x4f,
					0x8a, 0xfc, 0xc2, 0x01, 0x03, 0x5f, 0x7b, 0x6d, 0x8e,
					0x69, 0x40, 0x2d, 0xe5, 0x45, 0x16, 0x18, 0xc2, 0x1a,
					0x53, 0x5f, 0xa9, 0xd7, 0xbf, 0xc5, 0xb8, 0xdd, 0x9f,
					0xc2, 0x43, 0xf8, 0xcf, 0x92, 0x7d, 0xb3, 0x13, 0x22,
					0xd6, 0xe8, 0x81, 0xea, 0xa9, 0x1a, 0x99, 0x61, 0x70,
					0xe6, 0x57, 0xa0, 0x5a, 0x26, 0x64, 0x26, 0xd9, 0x8c,
					0x88, 0x00, 0x3f, 0x84, 0x77, 0xc1, 0x22, 0x70, 0x94,
					0xa0, 0xd9, 0xfa, 0x1e, 0x8c, 0x40, 0x24, 0x30, 0x9c,
					0xe1, 0xec, 0xcc, 0xb5, 0x21, 0x00, 0x35, 0xd4, 0x7a,
					0xc7, 0x2e, 0x8a,
				},
			},
			// Example 1.2
			{
				[]byte{0x75, 0x0c, 0x40, 0x47, 0xf5, 0x47, 0xe8, 0xe4,
					0x14, 0x11, 0x85, 0x65, 0x23, 0x29, 0x8a, 0xc9, 0xba,
					0xe2, 0x45, 0xef, 0xaf, 0x13, 0x97, 0xfb, 0xe5, 0x6f,
					0x9d, 0xd5,
				},
				[]byte{0x0c, 0xc7, 0x42, 0xce, 0x4a, 0x9b, 0x7f, 0x32,
					0xf9, 0x51, 0xbc, 0xb2, 0x51, 0xef, 0xd9, 0x25, 0xfe,
					0x4f, 0xe3, 0x5f,
				},
				[]byte{0x64, 0x0d, 0xb1, 0xac, 0xc5, 0x8e, 0x05, 0x68,
					0xfe, 0x54, 0x07, 0xe5, 0xf9, 0xb7, 0x01, 0xdf, 0xf8,
					0xc3, 0xc9, 0x1e, 0x71, 0x6c, 0x53, 0x6f, 0xc7, 0xfc,
					0xec, 0x6c, 0xb5, 0xb7, 0x1c, 0x11, 0x65, 0x98, 0x8d,
					0x4a, 0x27, 0x9e, 0x15, 0x77, 0xd7, 0x30, 0xfc, 0x7a,
					0x29, 0x93, 0x2e, 0x3f, 0x00, 0xc8, 0x15, 0x15, 0x23,
					0x6d, 0x8d, 0x8e, 0x31, 0x01, 0x7a, 0x7a, 0x09, 0xdf,
					0x43, 0x52, 0xd9, 0x04, 0xcd, 0xeb, 0x79, 0xaa, 0x58,
					0x3a, 0xdc, 0xc3, 0x1e, 0xa6, 0x98, 0xa4, 0xc0, 0x52,
					0x83, 0xda, 0xba, 0x90, 0x89, 0xbe, 0x54, 0x91, 0xf6,
					0x7c, 0x1a, 0x4e, 0xe4, 0x8d, 0xc7, 0x4b, 0xbb, 0xe6,
					0x64, 0x3a, 0xef, 0x84, 0x66, 0x79, 0xb4, 0xcb, 0x39,
					0x5a, 0x35, 0x2d, 0x5e, 0xd1, 0x15, 0x91, 0x2d, 0xf6,
					0x96, 0xff, 0xe0, 0x70, 0x29, 0x32, 0x94, 0x6d, 0x71,
					0x49, 0x2b, 0x44,
				},
			},
			// Example 1.3
			{
				[]byte{0xd9, 0x4a, 0xe0, 0x83, 0x2e, 0x64, 0x45, 0xce,
					0x42, 0x33, 0x1c, 0xb0, 0x6d, 0x53, 0x1a, 0x82, 0xb1,
					0xdb, 0x4b, 0xaa, 0xd3, 0x0f, 0x74, 0x6d, 0xc9, 0x16,
					0xdf, 0x24, 0xd4, 0xe3, 0xc2, 0x45, 0x1f, 0xff, 0x59,
					0xa6, 0x42, 0x3e, 0xb0, 0xe1, 0xd0, 0x2d, 0x4f, 0xe6,
					0x46, 0xcf, 0x69, 0x9d, 0xfd, 0x81, 0x8c, 0x6e, 0x97,
					0xb0, 0x51,
				},
				[]byte{0x25, 0x14, 0xdf, 0x46, 0x95, 0x75, 0x5a, 0x67,
					0xb2, 0x88, 0xea, 0xf4, 0x90, 0x5c, 0x36, 0xee, 0xc6,
					0x6f, 0xd2, 0xfd,
				},
				[]byte{0x42, 0x37, 0x36, 0xed, 0x03, 0x5f, 0x60, 0x26,
					0xaf, 0x27, 0x6c, 0x35, 0xc0, 0xb3, 0x74, 0x1b, 0x36,
					0x5e, 0x5f, 0x76, 0xca, 0x09, 0x1b, 0x4e, 0x8c, 0x29,
					0xe2, 0xf0, 0xbe, 0xfe, 0xe6, 0x03, 0x59, 0x5a, 0xa8,
					0x32, 0x2d, 0x60, 0x2d, 0x2e, 0x62, 0x5e, 0x95, 0xeb,
					0x81, 0xb2, 0xf1, 0xc9, 0x72, 0x4e, 0x82, 0x2e, 0xca,
					0x76, 0xdb, 0x86, 0x18, 0xcf, 0x09, 0xc5, 0x34, 0x35,
					0x03, 0xa4, 0x36, 0x08, 0x35, 0xb5, 0x90, 0x3b, 0xc6,
					0x37, 0xe3, 0x87, 0x9f, 0xb0, 0x5e, 0x0e, 0xf3, 0x26,
					0x85, 0xd5, 0xae, 0xc5, 0x06, 0x7c, 0xd7, 0xcc, 0x96,
					0xfe, 0x4b, 0x26, 0x70, 0xb6, 0xea, 0xc3, 0x06, 0x6b,
					0x1f, 0xcf, 0x56, 0x86, 0xb6, 0x85, 0x89, 0xaa, 0xfb,
					0x7d, 0x62, 0x9b, 0x02, 0xd8, 0xf8, 0x62, 0x5c, 0xa3,
					0x83, 0x36, 0x24, 0xd4, 0x80, 0x0f, 0xb0, 0x81, 0xb1,
					0xcf, 0x94, 0xeb,
				},
			},
		},
	},
	// Key 10
	{"ae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb",
		65537,
		"056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79",
		[]testEncryptOAEPMessage{
			// Example 10.1
			{
				[]byte{0x8b, 0xba, 0x6b, 0xf8, 0x2a, 0x6c, 0x0f, 0x86,
					0xd5, 0xf1, 0x75, 0x6e, 0x97, 0x95, 0x68, 0x70, 0xb0,
					0x89, 0x53, 0xb0, 0x6b, 0x4e, 0xb2, 0x05, 0xbc, 0x16,
					0x94, 0xee,
				},
				[]byte{0x47, 0xe1, 0xab, 0x71, 0x19, 0xfe, 0xe5, 0x6c,
					0x95, 0xee, 0x5e, 0xaa, 0xd8, 0x6f, 0x40, 0xd0, 0xaa,
					0x63, 0xbd, 0x33,
				},
				[]byte{0x53, 0xea, 0x5d, 0xc0, 0x8c, 0xd2, 0x60, 0xfb,
					0x3b, 0x85, 0x85, 0x67, 0x28, 0x7f, 0xa9, 0x15, 0x52,
					0xc3, 0x0b, 0x2f, 0xeb, 0xfb, 0xa2, 0x13, 0xf0, 0xae,
					0x87, 0x70, 0x2d, 0x06, 0x8d, 0x19, 0xba, 0xb0, 0x7f,
					0xe5, 0x74, 0x52, 0x3d, 0xfb, 0x42, 0x13, 0x9d, 0x68,
					0xc3, 0xc5, 0xaf, 0xee, 0xe0, 0xbf, 0xe4, 0xcb, 0x79,
					0x69, 0xcb, 0xf3, 0x82, 0xb8, 0x04, 0xd6, 0xe6, 0x13,
					0x96, 0x14, 0x4e, 0x2d, 0x0e, 0x60, 0x74, 0x1f, 0x89,
					0x93, 0xc3, 0x01, 0x4b, 0x58, 0xb9, 0xb1, 0x95, 0x7a,
					0x8b, 0xab, 0xcd, 0x23, 0xaf, 0x85, 0x4f, 0x4c, 0x35,
					0x6f, 0xb1, 0x66, 0x2a, 0xa7, 0x2b, 0xfc, 0xc7, 0xe5,
					0x86, 0x55, 0x9d, 0xc4, 0x28, 0x0d, 0x16, 0x0c, 0x12,
					0x67, 0x85, 0xa7, 0x23, 0xeb, 0xee, 0xbe, 0xff, 0x71,
					0xf1, 0x15, 0x94, 0x44, 0x0a, 0xae, 0xf8, 0x7d, 0x10,
					0x79, 0x3a, 0x87, 0x74, 0xa2, 0x39, 0xd4, 0xa0, 0x4c,
					0x87, 0xfe, 0x14, 0x67, 0xb9, 0xda, 0xf8, 0x52, 0x08,
					0xec, 0x6c, 0x72, 0x55, 0x79, 0x4a, 0x96, 0xcc, 0x29,
					0x14, 0x2f, 0x9a, 0x8b, 0xd4, 0x18, 0xe3, 0xc1, 0xfd,
					0x67, 0x34, 0x4b, 0x0c, 0xd0, 0x82, 0x9d, 0xf3, 0xb2,
					0xbe, 0xc6, 0x02, 0x53, 0x19, 0x62, 0x93, 0xc6, 0xb3,
					0x4d, 0x3f, 0x75, 0xd3, 0x2f, 0x21, 0x3d, 0xd4, 0x5c,
					0x62, 0x73, 0xd5, 0x05, 0xad, 0xf4, 0xcc, 0xed, 0x10,
					0x57, 0xcb, 0x75, 0x8f, 0xc2, 0x6a, 0xee, 0xfa, 0x44,
					0x12, 0x55, 0xed, 0x4e, 0x64, 0xc1, 0x99, 0xee, 0x07,
					0x5e, 0x7f, 0x16, 0x64, 0x61, 0x82, 0xfd, 0xb4, 0x64,
					0x73, 0x9b, 0x68, 0xab, 0x5d, 0xaf, 0xf0, 0xe6, 0x3e,
					0x95, 0x52, 0x01, 0x68, 0x24, 0xf0, 0x54, 0xbf, 0x4d,
					0x3c, 0x8c, 0x90, 0xa9, 0x7b, 0xb6, 0xb6, 0x55, 0x32,
					0x84, 0xeb, 0x42, 0x9f, 0xcc,
				},
			},
		},
	},
}
