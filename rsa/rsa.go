// Copyright 2019 gocrypto Author. All Rights Reserved.
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

// Package rsa provides RSA encryption and decryption, signature and verification functions.
package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/houseme/gocrypto"
)

type rsaCrypt struct {
	secretInfo SecretInfo
}

// SecretInfo secret info
type SecretInfo struct {
	PublicKey          string
	PublicKeyDataType  gocrypto.Encode
	PrivateKey         string
	PrivateKeyDataType gocrypto.Encode
	PrivateKeyType     gocrypto.Secret
	HashType           gocrypto.Hash
}

// NewRSACrypt init with the RSA secret info
func NewRSACrypt(secretInfo SecretInfo) *rsaCrypt {
	return &rsaCrypt{secretInfo: secretInfo}
}

// SetHashType set hash types
func (rc *rsaCrypt) SetHashType(hashType gocrypto.Hash) {
	rc.secretInfo.HashType = hashType
}

// Encrypt encrypts the given message with public key
// src the original data
// outputDataType encode type of encrypted data,such as Base64,HEX
func (rc *rsaCrypt) Encrypt(src string, outputDataType gocrypto.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return "", errors.New("secretInfo PublicKey can't be empty")
	}
	pubKeyDecoded, err := gocrypto.DecodeString(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDecoded)
	if err != nil {
		return
	}
	if secretInfo.HashType > gocrypto.Sha512256 {
		return "", errors.New("secretInfo HashType can't be supported")
	}
	hash, _ := gocrypto.GetHashFunc(secretInfo.HashType)
	var (
		srcBytes      = []byte(src)
		public        = pubKey.(*rsa.PublicKey)
		random        = rand.Reader
		msgLen        = len(srcBytes)
		step          = public.Size() - 2*hash().Size() - 2
		dataEncrypted []byte
	)
	for start := 0; start < msgLen; start += step {
		var (
			encryptedBlockBytes []byte
			finish              = start + step
		)
		if finish > msgLen {
			finish = msgLen
		}

		if encryptedBlockBytes, err = rsa.EncryptPKCS1v15(random, public, srcBytes[start:finish]); err != nil {
			return "", err
		}

		dataEncrypted = append(dataEncrypted, encryptedBlockBytes...)
	}
	return gocrypto.EncodeToString(dataEncrypted, outputDataType)
}

// Decrypt decrypts a plaintext using private key,
// src the encrypted data with the public key,
// srcType encode type of encrypted data,such as Base64,HEX
func (rc *rsaCrypt) Decrypt(src string, srcType gocrypto.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", errors.New("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := gocrypto.DecodeString(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return
	}
	private, err := gocrypto.ParsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return
	}
	decodeData, err := gocrypto.DecodeString(src, srcType)
	if err != nil {
		return
	}

	var (
		random        = rand.Reader
		msgLen        = len(decodeData)
		step          = private.PublicKey.Size()
		dataDecrypted []byte
	)
	for start := 0; start < msgLen; start += step {
		var (
			decryptedBlockBytes []byte
			finish              = start + step
		)

		if finish > msgLen {
			finish = msgLen
		}

		if decryptedBlockBytes, err = rsa.DecryptPKCS1v15(random, private, decodeData[start:finish]); err != nil {
			return
		}

		dataDecrypted = append(dataDecrypted, decryptedBlockBytes...)
	}

	return string(dataDecrypted), nil
}

// Sign calculates the signature of input data with the hash type & private key
// src the original unsigned data
// hashType the type of hash ,such as MD5,SHA1...
// outputDataType encode types of sign data, such as Base64,HEX
func (rc *rsaCrypt) Sign(src string, outputDataType gocrypto.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", errors.New("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := gocrypto.DecodeString(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return
	}
	prvKey, err := gocrypto.ParsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return
	}
	if secretInfo.HashType > gocrypto.Sha512256 {
		return "", errors.New("secretInfo HashType can't be supported")
	}

	cryptoHash, hashed, err := gocrypto.GetHash([]byte(src), secretInfo.HashType)
	if err != nil {
		return
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, prvKey, cryptoHash, hashed)
	if err != nil {
		return
	}
	return gocrypto.EncodeToString(signature, outputDataType)
}

// VerifySign verifies input data whether match the sign data with the public key
// src the original unsigned data
// signedData the data signed with private key
// hashType the type of hash ,such as MD5,SHA1...
// signDataType encode type of sign data,such as Base64,HEX
func (rc *rsaCrypt) VerifySign(src, signedData string, signDataType gocrypto.Encode) (bool, error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return false, errors.New("secretInfo PublicKey can't be empty")
	}
	publicKeyDecoded, err := gocrypto.DecodeString(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return false, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyDecoded)
	if err != nil {
		return false, err
	}

	if secretInfo.HashType > gocrypto.Sha512256 {
		return false, errors.New("secretInfo HashType can't be supported")
	}

	cryptoHash, hashed, err := gocrypto.GetHash([]byte(src), secretInfo.HashType)
	if err != nil {
		return false, err
	}
	signDecoded, err := gocrypto.DecodeString(signedData, signDataType)
	if err != nil {
		return false, err
	}
	if err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), cryptoHash, hashed, signDecoded); err != nil {
		return false, err
	}
	return true, nil
}

// EncryptByPriKey encrypts the given message with private key
// src the original data
// outputDataType encode type of encrypted data,such as Base64,HEX
func (rc *rsaCrypt) EncryptByPriKey(src string, outputDataType gocrypto.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", errors.New("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := gocrypto.DecodeString(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return
	}
	prvKey, err := gocrypto.ParsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return
	}

	output := bytes.NewBuffer(nil)
	err = priKeyIO(prvKey, bytes.NewReader([]byte(src)), output, true)
	if err != nil {
		return "", err
	}

	return gocrypto.EncodeToString(output.Bytes(), outputDataType)
}

// DecryptByPublic decrypts a plaintext using public key
// src the encrypted data with private key
// srcType encode type of encrypted data,such as Base64,HEX
func (rc *rsaCrypt) DecryptByPublic(src string, srcType gocrypto.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return "", errors.New("secretInfo PublicKey can't be empty")
	}
	pubKeyDecoded, err := gocrypto.DecodeString(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDecoded)
	if err != nil {
		return
	}

	decodeData, err := gocrypto.DecodeString(src, srcType)
	if err != nil {
		return
	}

	output := bytes.NewBuffer(nil)
	err = pubKeyIO(pubKey.(*rsa.PublicKey), bytes.NewReader(decodeData), output, false)
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

// EncryptOAEP encrypts the given message with RSA-OAEP
func (rc *rsaCrypt) EncryptOAEP(src string, outputDataType gocrypto.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return "", errors.New("secretInfo PublicKey can't be empty")
	}
	pubKeyDecoded, err := gocrypto.DecodeString(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDecoded)
	if err != nil {
		return
	}

	if secretInfo.HashType > gocrypto.Sha512256 {
		return "", errors.New("secretInfo HashType can't be supported")
	}
	hash, _ := gocrypto.GetHashFunc(secretInfo.HashType)

	var (
		srcBytes      = []byte(src)
		public        = pubKey.(*rsa.PublicKey)
		random        = rand.Reader
		msgLen        = len(srcBytes)
		hashType      = hash()
		step          = public.Size() - 2*hashType.Size() - 2
		dataEncrypted []byte
	)
	for start := 0; start < msgLen; start += step {
		var (
			encryptedBlockBytes []byte
			finish              = start + step
		)
		if finish > msgLen {
			finish = msgLen
		}

		if encryptedBlockBytes, err = rsa.EncryptOAEP(hashType, random, public, srcBytes[start:finish], nil); err != nil {
			return "", err
		}

		dataEncrypted = append(dataEncrypted, encryptedBlockBytes...)
	}
	return gocrypto.EncodeToString(dataEncrypted, outputDataType)
}

// DecryptOAEP decrypts a plaintext using RSA-OAEP
func (rc *rsaCrypt) DecryptOAEP(src string, srcType gocrypto.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", errors.New("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := gocrypto.DecodeString(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return
	}
	private, err := gocrypto.ParsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return
	}
	decodeData, err := gocrypto.DecodeString(src, srcType)
	if err != nil {
		return
	}

	if secretInfo.HashType > gocrypto.Sha512256 {
		return "", errors.New("secretInfo HashType can't be supported")
	}
	hash, _ := gocrypto.GetHashFunc(secretInfo.HashType)

	var (
		random         = rand.Reader
		msgLen         = len(decodeData)
		step           = private.PublicKey.Size()
		hashType       = hash()
		decryptedBytes []byte
	)
	for start := 0; start < msgLen; start += step {
		var (
			decryptedBlockBytes []byte
			finish              = start + step
		)

		if finish > msgLen {
			finish = msgLen
		}

		if decryptedBlockBytes, err = rsa.DecryptOAEP(hashType, random, private, decodeData[start:finish], nil); err != nil {
			return "", err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return string(decryptedBytes), nil
}
