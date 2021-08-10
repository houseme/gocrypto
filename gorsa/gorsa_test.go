package gorsa

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"math/big"
	"reflect"
	"testing"
)

// @Project: gocrypto
// @Author: houseme
// @Description:
// @File: gorsa_test
// @Version: 1.0.0
// @Date: 2021/8/10 15:54
// @Package gorsa

var Pubkey = `-----BEGIN Public key-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk+89V7vpOj1rG6bTAKYM
56qmFLwNCBVDJ3MltVVtxVUUByqc5b6u909MmmrLBqS//PWC6zc3wZzU1+ayh8xb
UAEZuA3EjlPHIaFIVIz04RaW10+1xnby/RQE23tDqsv9a2jv/axjE/27b62nzvCW
eItu1kNQ3MGdcuqKjke+LKhQ7nWPRCOd/ffVqSuRvG0YfUEkOz/6UpsPr6vrI331
hWRB4DlYy8qFUmDsyvvExe4NjZWblXCqkEXRRAhi2SQRCl3teGuIHtDUxCskRIDi
aMD+Qt2Yp+Vvbz6hUiqIWSIH1BoHJer/JOq2/O6X3cmuppU4AdVNgy8Bq236iXvr
MQIDAQAB
-----END Public key-----
`

var Pirvatekey = `-----BEGIN Private key-----
MIIEpAIBAAKCAQEAk+89V7vpOj1rG6bTAKYM56qmFLwNCBVDJ3MltVVtxVUUByqc
5b6u909MmmrLBqS//PWC6zc3wZzU1+ayh8xbUAEZuA3EjlPHIaFIVIz04RaW10+1
xnby/RQE23tDqsv9a2jv/axjE/27b62nzvCWeItu1kNQ3MGdcuqKjke+LKhQ7nWP
RCOd/ffVqSuRvG0YfUEkOz/6UpsPr6vrI331hWRB4DlYy8qFUmDsyvvExe4NjZWb
lXCqkEXRRAhi2SQRCl3teGuIHtDUxCskRIDiaMD+Qt2Yp+Vvbz6hUiqIWSIH1BoH
Jer/JOq2/O6X3cmuppU4AdVNgy8Bq236iXvrMQIDAQABAoIBAQCCbxZvHMfvCeg+
YUD5+W63dMcq0QPMdLLZPbWpxMEclH8sMm5UQ2SRueGY5UBNg0WkC/R64BzRIS6p
jkcrZQu95rp+heUgeM3C4SmdIwtmyzwEa8uiSY7Fhbkiq/Rly6aN5eB0kmJpZfa1
6S9kTszdTFNVp9TMUAo7IIE6IheT1x0WcX7aOWVqp9MDXBHV5T0Tvt8vFrPTldFg
IuK45t3tr83tDcx53uC8cL5Ui8leWQjPh4BgdhJ3/MGTDWg+LW2vlAb4x+aLcDJM
CH6Rcb1b8hs9iLTDkdVw9KirYQH5mbACXZyDEaqj1I2KamJIU2qDuTnKxNoc96HY
2XMuSndhAoGBAMPwJuPuZqioJfNyS99x++ZTcVVwGRAbEvTvh6jPSGA0k3cYKgWR
NnssMkHBzZa0p3/NmSwWc7LiL8whEFUDAp2ntvfPVJ19Xvm71gNUyCQ/hojqIAXy
tsNT1gBUTCMtFZmAkUsjqdM/hUnJMM9zH+w4lt5QM2y/YkCThoI65BVbAoGBAMFI
GsIbnJDNhVap7HfWcYmGOlWgEEEchG6Uq6Lbai9T8c7xMSFc6DQiNMmQUAlgDaMV
b6izPK4KGQaXMFt5h7hekZgkbxCKBd9xsLM72bWhM/nd/HkZdHQqrNAPFhY6/S8C
IjRnRfdhsjBIA8K73yiUCsQlHAauGfPzdHET8ktjAoGAQdxeZi1DapuirhMUN9Zr
kr8nkE1uz0AafiRpmC+cp2Hk05pWvapTAtIXTo0jWu38g3QLcYtWdqGa6WWPxNOP
NIkkcmXJjmqO2yjtRg9gevazdSAlhXpRPpTWkSPEt+o2oXNa40PomK54UhYDhyeu
akuXQsD4mCw4jXZJN0suUZMCgYAgzpBcKjulCH19fFI69RdIdJQqPIUFyEViT7Hi
bsPTTLham+3u78oqLzQukmRDcx5ddCIDzIicMfKVf8whertivAqSfHytnf/pMW8A
vUPy5G3iF5/nHj76CNRUbHsfQtv+wqnzoyPpHZgVQeQBhcoXJSm+qV3cdGjLU6OM
HgqeaQKBgQCnmL5SX7GSAeB0rSNugPp2GezAQj0H4OCc8kNrHK8RUvXIU9B2zKA2
z/QUKFb1gIGcKxYr+LqQ25/+TGvINjuf6P3fVkHL0U8jOG0IqpPJXO3Vl9B8ewWL
cFQVB/nQfmaMa4ChK0QEUe+Mqi++MwgYbRHx1lIOXEfUJO+PXrMekw==
-----END Private key-----
`

// TestDemo .
func TestDemo(t *testing.T) {
	// Public key encryption private key decryption
	if err := applyPubEPriD(); err != nil {
		log.Println(err)
	}
	// Public key decryption private key encryption
	if err := applyPriEPubD(); err != nil {
		log.Println(err)
	}
}

// Public key encryption private key decryption
func applyPubEPriD() error {
	pubenctypt, err := PublicEncrypt(`hello world`, Pubkey)
	if err != nil {
		return err
	}

	pridecrypt, err := PriKeyDecrypt(pubenctypt, Pirvatekey)
	if err != nil {
		return err
	}
	if string(pridecrypt) != `hello world` {
		return errors.New(`decryption failed`)
	}
	return nil
}

// Public key decryption private key encryption
func applyPriEPubD() error {
	prienctypt, err := PriKeyEncrypt(`hello world`, Pirvatekey)
	if err != nil {
		return err
	}

	pubdecrypt, err := PublicDecrypt(prienctypt, Pubkey)
	if err != nil {
		return err
	}
	if string(pubdecrypt) != `hello world` {
		return errors.New(`decryption failed`)
	}
	return nil
}

func TestNewRSASecurity(t *testing.T) {
	type args struct {
		pubStr string
		priStr string
	}
	tests := []struct {
		name string
		args args
		want *RSASecurity
	}{
		// TODO: Add test cases.
		{
			name: "cesi1",
			args: args{
				pubStr: Pubkey,
				priStr: Pirvatekey,
			},
			want: NewRSASecurity(Pubkey, Pirvatekey),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRSASecurity(tt.args.pubStr, tt.args.priStr); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRSASecurity() = %v, want %v", got, tt.want)
			}
		})
	}
	r := NewRSASecurity(Pubkey, Pirvatekey)
	data := `hello world`
	rsaData, err := r.PriKeyEncrypt([]byte(data))
	if err != nil {
		t.Errorf("NewRSASecurity() = %v, err %v", rsaData, err)
	}
	data = base64.StdEncoding.EncodeToString(rsaData)

	databs, _ := base64.StdEncoding.DecodeString(data)
	databs, err = r.PubKeyDecrypt(databs)
	if err != nil {
		t.Errorf("NewRSASecurity() = %v, err %v", rsaData, err)
	}
	t.Log("result:", string(databs))
}

func TestPriKeyDecrypt(t *testing.T) {
	type args struct {
		data       string
		privateKey string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PriKeyDecrypt(tt.args.data, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("PriKeyDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PriKeyDecrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPriKeyEncrypt(t *testing.T) {
	type args struct {
		data       string
		privateKey string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PriKeyEncrypt(tt.args.data, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("PriKeyEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PriKeyEncrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicDecrypt(t *testing.T) {
	type args struct {
		data      string
		publicKey string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PublicDecrypt(tt.args.data, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicDecrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicEncrypt(t *testing.T) {
	type args struct {
		data      string
		publicKey string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PublicEncrypt(tt.args.data, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PublicEncrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_GetPrivateKey(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	tests := []struct {
		name    string
		fields  fields
		want    *rsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.GetPrivateKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPrivateKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_GetPublicKey(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	tests := []struct {
		name    string
		fields  fields
		want    *rsa.PublicKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.GetPublicKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPublicKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_PriKeyDecrypt(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		input []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.PriKeyDecrypt(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("PriKeyDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PriKeyDecrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_PriKeyEncrypt(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		input []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.PriKeyEncrypt(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("PriKeyEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PriKeyEncrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_PubKeyDecrypt(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		input []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.PubKeyDecrypt(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("PubKeyDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PubKeyDecrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_PubKeyEncrypt(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		input []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.PubKeyEncrypt(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("PubKeyEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PubKeyEncrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_SetPrivateKey(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		priStr string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			if err := r.SetPrivateKey(tt.args.priStr); (err != nil) != tt.wantErr {
				t.Errorf("SetPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRSASecurity_SetPublicKey(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		pubStr string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			if err := r.SetPublicKey(tt.args.pubStr); (err != nil) != tt.wantErr {
				t.Errorf("SetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRSASecurity_SignSha1WithRsa(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		data string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.SignSha1WithRsa(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignSha1WithRsa() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignSha1WithRsa() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_SignSha256WithRsa(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		data string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			got, err := r.SignSha256WithRsa(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignSha256WithRsa() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignSha256WithRsa() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASecurity_VerifySignSha1WithRsa(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		data     string
		signData string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			if err := r.VerifySignSha1WithRsa(tt.args.data, tt.args.signData); (err != nil) != tt.wantErr {
				t.Errorf("VerifySignSha1WithRsa() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRSASecurity_VerifySignSha256WithRsa(t *testing.T) {
	type fields struct {
		pubStr string
		priStr string
		pubKey *rsa.PublicKey
		priKey *rsa.PrivateKey
	}
	type args struct {
		data     string
		signData string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RSASecurity{
				pubStr: tt.fields.pubStr,
				priStr: tt.fields.priStr,
				pubKey: tt.fields.pubKey,
				priKey: tt.fields.priKey,
			}
			if err := r.VerifySignSha256WithRsa(tt.args.data, tt.args.signData); (err != nil) != tt.wantErr {
				t.Errorf("VerifySignSha256WithRsa() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignSha1WithRsa(t *testing.T) {
	type args struct {
		data       string
		privateKey string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignSha1WithRsa(tt.args.data, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignSha1WithRsa() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignSha1WithRsa() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignSha256WithRsa(t *testing.T) {
	type args struct {
		data       string
		privateKey string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignSha256WithRsa(tt.args.data, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignSha256WithRsa() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignSha256WithRsa() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifySignSha1WithRsa(t *testing.T) {
	type args struct {
		data      string
		signData  string
		publicKey string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifySignSha1WithRsa(tt.args.data, tt.args.signData, tt.args.publicKey); (err != nil) != tt.wantErr {
				t.Errorf("VerifySignSha1WithRsa() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifySignSha256WithRsa(t *testing.T) {
	type args struct {
		data      string
		signData  string
		publicKey string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifySignSha256WithRsa(tt.args.data, tt.args.signData, tt.args.publicKey); (err != nil) != tt.wantErr {
				t.Errorf("VerifySignSha256WithRsa() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_copyWithLeftPad(t *testing.T) {
	type args struct {
		dest []byte
		src  []byte
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
}

func Test_decrypt(t *testing.T) {
	type args struct {
		random io.Reader
		priv   *rsa.PrivateKey
		c      *big.Int
	}
	tests := []struct {
		name    string
		args    args
		wantM   *big.Int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotM, err := decrypt(tt.args.random, tt.args.priv, tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotM, tt.wantM) {
				t.Errorf("decrypt() gotM = %v, want %v", gotM, tt.wantM)
			}
		})
	}
}

func Test_encrypt(t *testing.T) {
	type args struct {
		c   *big.Int
		pub *rsa.PublicKey
		m   *big.Int
	}
	tests := []struct {
		name string
		args args
		want *big.Int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encrypt(tt.args.c, tt.args.pub, tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPriKey(t *testing.T) {
	type args struct {
		privateKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *rsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPriKey(tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPriKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPriKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPubKey(t *testing.T) {
	type args struct {
		publicKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *rsa.PublicKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPubKey(tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPubKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_leftPad(t *testing.T) {
	type args struct {
		input []byte
		size  int
	}
	tests := []struct {
		name    string
		args    args
		wantOut []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOut := leftPad(tt.args.input, tt.args.size); !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("leftPad() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func Test_modInverse(t *testing.T) {
	type args struct {
		a *big.Int
		n *big.Int
	}
	tests := []struct {
		name   string
		args   args
		wantIa *big.Int
		wantOk bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIa, gotOk := modInverse(tt.args.a, tt.args.n)
			if !reflect.DeepEqual(gotIa, tt.wantIa) {
				t.Errorf("modInverse() gotIa = %v, want %v", gotIa, tt.wantIa)
			}
			if gotOk != tt.wantOk {
				t.Errorf("modInverse() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func Test_nonZeroRandomBytes(t *testing.T) {
	type args struct {
		s    []byte
		rand io.Reader
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := nonZeroRandomBytes(tt.args.s, tt.args.rand); (err != nil) != tt.wantErr {
				t.Errorf("nonZeroRandomBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_priKeyByte(t *testing.T) {
	type args struct {
		pri       *rsa.PrivateKey
		in        []byte
		isEncrypt bool
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := priKeyByte(tt.args.pri, tt.args.in, tt.args.isEncrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("priKeyByte() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("priKeyByte() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_priKeyEncrypt(t *testing.T) {
	type args struct {
		rand   io.Reader
		priv   *rsa.PrivateKey
		hashed []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := priKeyEncrypt(tt.args.rand, tt.args.priv, tt.args.hashed)
			if (err != nil) != tt.wantErr {
				t.Errorf("priKeyEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("priKeyEncrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_priKeyIO(t *testing.T) {
	type args struct {
		pri       *rsa.PrivateKey
		r         io.Reader
		isEncrypt bool
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := priKeyIO(tt.args.pri, tt.args.r, w, tt.args.isEncrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("priKeyIO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("priKeyIO() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func Test_pubKeyByte(t *testing.T) {
	type args struct {
		pub       *rsa.PublicKey
		in        []byte
		isEncrytp bool
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pubKeyByte(tt.args.pub, tt.args.in, tt.args.isEncrytp)
			if (err != nil) != tt.wantErr {
				t.Errorf("pubKeyByte() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pubKeyByte() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pubKeyDecrypt(t *testing.T) {
	type args struct {
		pub  *rsa.PublicKey
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pubKeyDecrypt(tt.args.pub, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("pubKeyDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pubKeyDecrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pubKeyIO(t *testing.T) {
	type args struct {
		pub       *rsa.PublicKey
		in        io.Reader
		isEncrypt bool
	}
	tests := []struct {
		name    string
		args    args
		wantOut string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			err := pubKeyIO(tt.args.pub, tt.args.in, out, tt.args.isEncrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("pubKeyIO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOut := out.String(); gotOut != tt.wantOut {
				t.Errorf("pubKeyIO() gotOut = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}
