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

package gocrypto

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
)

// GetHash gets the crypto hash type & hashed data in different hash types
func GetHash(data []byte, hashType Hash) (h crypto.Hash, hashed []byte, err error) {
	if hashType > Sha512256 {
		return h, hashed, errors.New("hashType unsupported")
	}
	nh, h := GetHashFunc(hashType)
	hh := nh()
	if _, err = hh.Write(data); err != nil {
		return
	}
	hashed = hh.Sum(nil)
	return
}

// GetHashFunc gets the crypto hash func & type in different hash types
func GetHashFunc(hashType Hash) (f func() hash.Hash, h crypto.Hash) {
	switch hashType {
	case SHA1:
		f = sha1.New
		h = crypto.SHA1
	case SHA224:
		f = sha256.New224
		h = crypto.SHA224
	case SHA256:
		f = sha256.New
		h = crypto.SHA256
	case SHA384:
		f = sha512.New384
		h = crypto.SHA384
	case SHA512:
		f = sha512.New
		h = crypto.SHA512
	case Sha512224:
		f = sha512.New512_224
		h = crypto.SHA512_224
	case Sha512256:
		f = sha512.New512_256
		h = crypto.SHA512_256
	case MD5:
		f = md5.New
		h = crypto.MD5
	default:
		panic("unsupported hashType")
	}
	return
}

// DecodeString decodes string data to bytes in designed encoded type
func DecodeString(data string, encodedType Encode) (keyDecoded []byte, err error) {
	switch encodedType {
	case String:
		keyDecoded = []byte(data)
	case HEX:
		keyDecoded, err = hex.DecodeString(data)
	case Base64:
		keyDecoded, err = base64.StdEncoding.DecodeString(data)
	default:
		return keyDecoded, errors.New("secretInfo PublicKeyDataType unsupported")
	}
	return keyDecoded, err
}

// ParsePrivateKey parses private key bytes to rsa privateKey
func ParsePrivateKey(privateKeyDecoded []byte, keyType Secret) (*rsa.PrivateKey, error) {
	switch keyType {
	case PKCS1:
		return x509.ParsePKCS1PrivateKey(privateKeyDecoded)
	case PKCS8:
		keyParsed, err := x509.ParsePKCS8PrivateKey(privateKeyDecoded)
		return keyParsed.(*rsa.PrivateKey), err
	default:
		return &rsa.PrivateKey{}, errors.New("secretInfo PrivateKeyDataType unsupported")
	}
}

// EncodeToString encodes data to string with encode types
func EncodeToString(data []byte, encodeType Encode) (string, error) {
	switch encodeType {
	case HEX:
		return hex.EncodeToString(data), nil
	case Base64:
		return base64.StdEncoding.EncodeToString(data), nil
	case String:
		return string(data), nil
	default:
		return "", errors.New("secretInfo OutputType unsupported")
	}
}

// UnPaddingPKCS7 un-padding src data to original data , adapt to PKCS5 & PKCS7
func UnPaddingPKCS7(src []byte, blockSize int) []byte {
	n := len(src)
	if n == 0 {
		return src
	}
	paddingNum := int(src[n-1])
	if n < paddingNum || paddingNum > blockSize {
		return src
	}
	return src[:n-paddingNum]
}

// PKCS7Padding adds padding data using pkcs7 rules , adapt to PKCS5 &PKCS7
func PKCS7Padding(src []byte, blockSize int) []byte {
	paddingNum := blockSize - len(src)%blockSize
	padding := bytes.Repeat([]byte{byte(paddingNum)}, paddingNum)
	return append(src, padding...)
}
