package gorsa

// @Project: gocrypto
// @Author: houseme
// @Description:
// @File: gorsa
// @Version: 1.0.0
// @Date: 2021/8/10 15:24
// @Package gorsa

import (
	"encoding/base64"
)

// PublicEncrypt 公钥加密
func PublicEncrypt(data, publicKey string) (string, error) {

	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)

	rsadata, err := grsa.PubKeyEncrypt([]byte(data))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rsadata), nil
}

// PriKeyEncrypt 私钥加密
func PriKeyEncrypt(data, privateKey string) (string, error) {

	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	rsaData, err := grsa.PriKeyEncrypt([]byte(data))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rsaData), nil
}

// PublicDecrypt 公钥解密
func PublicDecrypt(data, publicKey string) ([]byte, error) {

	databs, _ := base64.StdEncoding.DecodeString(data)

	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)

	return grsa.PubKeyDecrypt([]byte(databs))
}

// PriKeyDecrypt 私钥解密
func PriKeyDecrypt(data, privateKey string) ([]byte, error) {

	databs, _ := base64.StdEncoding.DecodeString(data)

	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	return grsa.PriKeyDecrypt([]byte(databs))
}
