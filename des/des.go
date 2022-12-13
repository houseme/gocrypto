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

// Package des implements the DES encryption algorithm.
package des

import (
	"crypto/des"
	"fmt"

	"github.com/houseme/gocrypto"
)

type desCrypt struct {
	gocrypto.CipherCrypt
}

// NewDESCrypt news a DESCrypt pointer with a key
func NewDESCrypt(key []byte) *desCrypt {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return &desCrypt{CipherCrypt: gocrypto.CipherCrypt{Block: block}}
}

// NewDesCryptWithDecode decodes key and then news a DESCrypt pointer with the key decoded
func NewDesCryptWithDecode(key string, keyDataType gocrypto.Encode) *desCrypt {
	data, err := gocrypto.DecodeString(key, keyDataType)
	if err != nil {
		panic(fmt.Sprintf("gocrypto decode key error : %v ", err))
	}
	return NewDESCrypt(data)
}

type tripleDESCrypt struct {
	gocrypto.CipherCrypt
}

// NewTripleDESCrypt news a TripleDESCrypt pointer with a key
func NewTripleDESCrypt(key []byte) *tripleDESCrypt {
	if len(key) != 24 {
		panic("triple des key length must be 24")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	return &tripleDESCrypt{CipherCrypt: gocrypto.CipherCrypt{Block: block}}
}

// NewTripleDesCryptWithDecode decodes key and then news a TripleDESCrypt pointer with the key decoded
func NewTripleDesCryptWithDecode(key string, keyDataType gocrypto.Encode) *tripleDESCrypt {
	data, err := gocrypto.DecodeString(key, keyDataType)
	if err != nil {
		panic(fmt.Sprintf("gocrypto decode key error : %v ", err))
	}
	return NewTripleDESCrypt(data)
}
