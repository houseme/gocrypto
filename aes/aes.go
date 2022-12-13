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

// Package aes implements the AES encryption algorithm.
package aes

import (
	"crypto/aes"
	"fmt"

	"github.com/houseme/gocrypto"
)

type aesCrypt struct {
	gocrypto.CipherCrypt
}

// NewAESCrypt .
func NewAESCrypt(key []byte) *aesCrypt {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return &aesCrypt{CipherCrypt: gocrypto.CipherCrypt{Block: block}}
}

// NewAESCryptWithDecode .
func NewAESCryptWithDecode(key string, keyDataType gocrypto.Encode) *aesCrypt {
	data, err := gocrypto.DecodeString(key, keyDataType)
	if err != nil {
		panic(fmt.Sprintf("gocrypto decode key error : %v ", err))
	}
	return NewAESCrypt(data)
}
