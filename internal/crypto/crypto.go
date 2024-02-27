package crypto

import (
	"encoding/asn1"
	"fmt"

	"go.mozilla.org/pkcs7"
)

func GetCMSInfo(data []byte) (map[string]any, error) {

	result := map[string]any{}

	p7, err := pkcs7.Parse(data)
	if err != nil {
		return result, err
	}

	for _, c := range p7.Signers {
		for _, s := range c.AuthenticatedAttributes {
			if s.Type.String() == pkcs7.OIDAttributeContentType.String() {
				result["contentType"] = s.Value.Bytes
			} else if s.Type.Equal(pkcs7.OIDAttributeSigningTime) {
				result["signingTime"] = string(s.Value.Bytes)
			} else if s.Type.Equal(pkcs7.OIDAttributeMessageDigest) {
				shaStr := ""
				for _, b := range s.Value.Bytes {
					shaStr = fmt.Sprintf("%s%02x", shaStr, b)
				}
				result["messageDigest"] = string(shaStr)
			} else if s.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}) {
				result["cdhashes"] = string(s.Value.Bytes[4:])
			}
		}
	}

	// Check if is detached
	result["detached"] = p7.Content == nil
	result["content"] = p7.Content

	certs := []string{}
	for _, c := range p7.Certificates {
		certs = append(certs, fmt.Sprintf("issuer: %s, name: %s", c.Issuer.CommonName, c.Subject.CommonName))
	}
	result["certificates"] = certs

	return result, nil
}
