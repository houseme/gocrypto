package gorsa

// @Project: gocrypto
// @Author: houseme
// @Description:
// @File: sign
// @Version: 1.0.0
// @Date: 2021/8/10 15:25
// @Package gorsa

// SignSha1WithRsa 使用RSAWithSHA1算法签名
func SignSha1WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignSha1WithRsa(data)
	if err != nil {
		return "", err
	}

	return sign, err
}

// SignSha256WithRsa 使用RSAWithSHA256算法签名
func SignSha256WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignSha256WithRsa(data)
	if err != nil {
		return "", err
	}
	return sign, err
}

// VerifySignSha1WithRsa 使用RSAWithSHA1验证签名
func VerifySignSha1WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignSha1WithRsa(data, signData)
}

// VerifySignSha256WithRsa 使用RSAWithSHA256验证签名
func VerifySignSha256WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignSha256WithRsa(data, signData)
}
