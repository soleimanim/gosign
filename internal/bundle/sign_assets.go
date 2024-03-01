package bundle

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

type SignAssets struct {
	Certificate *x509.Certificate
	Privatekey  *rsa.PrivateKey
}

func ParseCertificates(
	certFilePath string,
	privateKeyFilePath string,
	provisioningFilePath string,
	entitlementsFilePath string,
	password string,
) (SignAssets, error) {
	assets := SignAssets{}

	// Read and parse private key
	privateKeyData, err := os.ReadFile(privateKeyFilePath)
	if err != nil {
		return assets, err
	}
	decodePrivateKeyData, _ := pem.Decode(privateKeyData)
	if decodePrivateKeyData == nil {
		return assets, errors.New("could not decode private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(decodePrivateKeyData.Bytes)
	if err != nil {
		return assets, err
	}

	certificateData, err := os.ReadFile(certFilePath)
	if err != nil {
		return assets, err
	}

	decodedCertificateData, _ := pem.Decode(certificateData)
	if decodedCertificateData == nil {
		return assets, errors.New("could not parse certificate")
	}
	certificate, err := x509.ParseCertificate(decodedCertificateData.Bytes)
	if err != nil {
		return assets, err
	}

	// TODO: read certificate from provisioning profile if certificate not peovided

	assets.Certificate = certificate
	assets.Privatekey = privateKey
	return assets, nil
}
