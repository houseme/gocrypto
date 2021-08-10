package gorsa

// @Project: gocrypto
// @Author: houseme
// @Description:
// @File: rsa
// @Version: 1.0.0
// @Date: 2021/8/10 15:19
// @Package gorsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/ioutil"
)

// RSA 。
var RSA = &RSASecurity{}

// RSASecurity 。
type RSASecurity struct {
	pubStr string          // 公钥字符串
	priStr string          // 私钥字符串
	pubKey *rsa.PublicKey  // 公钥
	priKey *rsa.PrivateKey // 私钥
}

// NewRSASecurity .
func NewRSASecurity(pubStr, priStr string) *RSASecurity {
	r := &RSASecurity{}
	r.SetPublicKey(pubStr)
	r.SetPrivateKey(priStr)
	return r
}

// SetPublicKey 设置公钥
func (r *RSASecurity) SetPublicKey(pubStr string) (err error) {
	r.pubStr = pubStr
	r.pubKey, err = r.GetPublicKey()
	return err
}

// SetPrivateKey 设置私钥
func (r *RSASecurity) SetPrivateKey(priStr string) (err error) {
	r.priStr = priStr
	r.priKey, err = r.GetPrivateKey()
	return err
}

// GetPrivateKey *rsa.PublicKey
func (r *RSASecurity) GetPrivateKey() (*rsa.PrivateKey, error) {
	return getPriKey([]byte(r.priStr))
}

// GetPublicKey *rsa.PrivateKey
func (r *RSASecurity) GetPublicKey() (*rsa.PublicKey, error) {
	return getPubKey([]byte(r.pubStr))
}

// PubKeyEncrypt 公钥加密
func (r *RSASecurity) PubKeyEncrypt(input []byte) ([]byte, error) {
	if r.pubKey == nil {
		return []byte(""), errors.New(`please set the public key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(r.pubKey, bytes.NewReader(input), output, true)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// PubKeyDecrypt 公钥解密
func (r *RSASecurity) PubKeyDecrypt(input []byte) ([]byte, error) {
	if r.pubKey == nil {
		return []byte(""), errors.New(`please set the public key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(r.pubKey, bytes.NewReader(input), output, false)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// PriKeyEncrypt 私钥加密
func (r *RSASecurity) PriKeyEncrypt(input []byte) ([]byte, error) {
	if r.priKey == nil {
		return []byte(""), errors.New(`please set the private key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(r.priKey, bytes.NewReader(input), output, true)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// PriKeyDecrypt 私钥解密
func (r *RSASecurity) PriKeyDecrypt(input []byte) ([]byte, error) {
	if r.priKey == nil {
		return []byte(""), errors.New(`please set the private key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(r.priKey, bytes.NewReader(input), output, false)
	if err != nil {
		return []byte(""), err
	}

	return ioutil.ReadAll(output)
}

// SignSha1WithRsa 使用RSAWithSHA1算法签名
func (r *RSASecurity) SignSha1WithRsa(data string) (string, error) {
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(data))
	hashed := sha1Hash.Sum(nil)

	signByte, err := rsa.SignPKCS1v15(rand.Reader, r.priKey, crypto.SHA1, hashed)
	sign := base64.StdEncoding.EncodeToString(signByte)
	return string(sign), err
}

// SignSha256WithRsa 使用RSAWithSHA256算法签名
func (r *RSASecurity) SignSha256WithRsa(data string) (string, error) {
	sha256Hash := sha256.New()
	sha256Hash.Write([]byte(data))
	hashed := sha256Hash.Sum(nil)

	signByte, err := rsa.SignPKCS1v15(rand.Reader, r.priKey, crypto.SHA256, hashed)
	sign := base64.StdEncoding.EncodeToString(signByte)
	return string(sign), err
}

// VerifySignSha1WithRsa 使用RSAWithSHA1验证签名
func (r *RSASecurity) VerifySignSha1WithRsa(data string, signData string) error {
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	hash := sha1.New()
	hash.Write([]byte(data))
	return rsa.VerifyPKCS1v15(r.pubKey, crypto.SHA1, hash.Sum(nil), sign)
}

// VerifySignSha256WithRsa 使用RSAWithSHA256验证签名
func (r *RSASecurity) VerifySignSha256WithRsa(data string, signData string) error {
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	hash := sha256.New()
	hash.Write([]byte(data))

	return rsa.VerifyPKCS1v15(r.pubKey, crypto.SHA256, hash.Sum(nil), sign)
}
