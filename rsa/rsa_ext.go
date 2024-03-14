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
	"crypto/x509"
	"errors"
	"io"
	"math/big"

	"github.com/houseme/gocrypto"
)

var (
	// ErrDataToLarge .
	ErrDataToLarge = errors.New("message too long for RSA public key size")
	// ErrDataLen .
	ErrDataLen = errors.New("data length error")
	// ErrDataBroken .
	ErrDataBroken = errors.New("data broken, first byte is not zero")
	// ErrKeyPairDisMatch .
	ErrKeyPairDisMatch = errors.New("data is not encrypted by the private key")
	// ErrDecryption .
	ErrDecryption = errors.New("decryption error")
	// ErrPublicKey .
	ErrPublicKey = errors.New("get public key error")
	// ErrPrivateKey .
	ErrPrivateKey = errors.New("get private key error")
)

// 设置公钥
func getPubKey(publicKey string, pubType gocrypto.Encode) (*rsa.PublicKey, error) {
	// decode public key
	if publicKey == "" {
		return nil, errors.New("secretInfo PublicKey can't be empty")
	}
	pubKeyDecoded, err := gocrypto.DecodeString(publicKey, pubType)
	if err != nil {
		return nil, err
	}
	// x509 parse public key
	pub, err := x509.ParsePKIXPublicKey(pubKeyDecoded)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), err
}

// 设置私钥
func getPriKey(privateKey string, priType gocrypto.Encode, priKeyType gocrypto.Secret) (*rsa.PrivateKey, error) {
	if privateKey == "" {
		return nil, errors.New("PrivateKey can't be empty")
	}

	privateKeyDecoded, err := gocrypto.DecodeString(privateKey, priType)
	if err != nil {
		return nil, err
	}

	return gocrypto.ParsePrivateKey(privateKeyDecoded, priKeyType)
}

// 公钥加密或解密 byte
func pubKeyByte(pub *rsa.PublicKey, in []byte, isEncrypt bool) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if isEncrypt {
		k = k - 11
	}
	if len(in) <= k {
		if isEncrypt {
			return rsa.EncryptPKCS1v15(rand.Reader, pub, in)
		}
		return pubKeyDecrypt(pub, in)
	}
	var (
		iv  = make([]byte, k)
		out = bytes.NewBuffer(iv)
	)

	if err := pubKeyIO(pub, bytes.NewReader(in), out, isEncrypt); err != nil {
		return nil, err
	}
	return io.ReadAll(out)
}

// 私钥加密或解密 byte
func priKeyByte(pri *rsa.PrivateKey, in []byte, isEncrypt bool) ([]byte, error) {
	k := (pri.N.BitLen() + 7) / 8
	if isEncrypt {
		k = k - 11
	}
	if len(in) <= k {
		if isEncrypt {
			return priKeyEncrypt(rand.Reader, pri, in)
		}
		return rsa.DecryptPKCS1v15(rand.Reader, pri, in)
	}
	var (
		iv  = make([]byte, k)
		out = bytes.NewBuffer(iv)
	)

	if err := priKeyIO(pri, bytes.NewReader(in), out, isEncrypt); err != nil {
		return nil, err
	}
	return io.ReadAll(out)
}

// 公钥加密或解密 Reader
func pubKeyIO(pub *rsa.PublicKey, in io.Reader, out io.Writer, isEncrypt bool) (err error) {
	k := (pub.N.BitLen() + 7) / 8
	if isEncrypt {
		k = k - 11
	}

	var (
		b    []byte
		buf  = make([]byte, k)
		size int
	)

	for {
		if size, err = in.Read(buf); err != nil {
			if err == io.EOF {
				return nil
			}
			return
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrypt {
			b, err = rsa.EncryptPKCS1v15(rand.Reader, pub, b)
		} else {
			b, err = pubKeyDecrypt(pub, b)
		}
		if err != nil {
			return
		}
		if _, err = out.Write(b); err != nil {
			return
		}
	}
}

// 私钥加密或解密 Reader
func priKeyIO(pri *rsa.PrivateKey, r io.Reader, w io.Writer, isEncrypt bool) (err error) {
	k := (pri.N.BitLen() + 7) / 8
	if isEncrypt {
		k = k - 11
	}

	var (
		b    []byte
		buf  = make([]byte, k)
		size int
	)

	for {
		if size, err = r.Read(buf); err != nil {
			if err == io.EOF {
				return nil
			}
			return
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrypt {
			b, err = priKeyEncrypt(rand.Reader, pri, b)
		} else {
			b, err = rsa.DecryptPKCS1v15(rand.Reader, pri, b)
		}
		if err != nil {
			return
		}
		if _, err = w.Write(b); err != nil {
			return
		}
	}
}

// 公钥解密
func pubKeyDecrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if k != len(data) {
		return nil, ErrDataLen
	}
	m := new(big.Int).SetBytes(data)
	if m.Cmp(pub.N) > 0 {
		return nil, ErrDataToLarge
	}
	m.Exp(m, big.NewInt(int64(pub.E)), pub.N)
	d := leftPad(m.Bytes(), k)
	if d[0] != 0 {
		return nil, ErrDataBroken
	}
	if d[1] != 0 && d[1] != 1 {
		return nil, ErrKeyPairDisMatch
	}
	var i = 2
	for ; i < len(d); i++ {
		if d[i] == 0 {
			break
		}
	}
	i++
	if i == len(d) {
		return nil, nil
	}
	return d[i:], nil
}

// 私钥加密
func priKeyEncrypt(rand io.Reader, priv *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	tLen := len(hashed)
	k := (priv.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, ErrDataLen
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], hashed)
	m := new(big.Int).SetBytes(em)
	c, err := decrypt(rand, priv, m)
	if err != nil {
		return nil, err
	}
	copyWithLeftPad(em, c.Bytes())
	return em, nil
}

// 从crypto/rsa复制
var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// 从crypto/rsa复制
func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// 从crypto/rsa复制
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		err = ErrDecryption
		return
	}
	var ir *big.Int
	if random != nil {
		var r *big.Int
		for {
			if r, err = rand.Int(random, priv.N); err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			if ir, ok = modInverse(r, priv.N); ok {
				break
			}
		}
		var (
			bigE  = big.NewInt(int64(priv.E))
			rpowe = new(big.Int).Exp(r, bigE, priv.N)
			cCopy = new(big.Int).Set(c)
		)

		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

// 从crypto/rsa复制
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

// 从crypto/rsa复制
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	if _, err = io.ReadFull(rand, s); err != nil {
		return
	}
	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			if _, err = io.ReadFull(rand, s[i:i+1]); err != nil {
				return
			}
			s[i] ^= 0x42
		}
	}
	return
}

// 从crypto/rsa复制
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

// 从crypto/rsa复制
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		return
	}
	if x.Cmp(bigOne) < 0 {
		x.Add(x, n)
	}
	return x, true
}
