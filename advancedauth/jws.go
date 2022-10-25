package advancedauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cloudentity/oauth2/internal"
	"github.com/cloudentity/oauth2/jws"
)

func signer(header *jws.Header, key string) (func(data []byte) (sig []byte, err error), error) {
	var hash crypto.Hash
	var alg string

	var a = header.Algorithm
	switch a {
	case "RS256":
		alg, hash = "RSA", crypto.SHA256
	case "RS384":
		alg, hash = "RSA", crypto.SHA384
	case "RS512":
		alg, hash = "RSA", crypto.SHA512
	case "ES256":
		alg, hash = "ECDSA", crypto.SHA256
	case "ES384":
		alg, hash = "ECDSA", crypto.SHA384
	case "ES512":
		alg, hash = "ECDSA", crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", a)
	}

	return func(data []byte) (sig []byte, err error) {
		h := hash.New()
		h.Write(data)
		if alg == "RSA" {
			rsaKey, err := internal.ParseKey([]byte(key))
			if err != nil {
				return nil, err
			}
			return rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, h.Sum(nil))
		} else if alg == "ECDSA" {
			ecdsaKey, err := ParsePrivateECDSAKey([]byte(key))
			if err != nil {
				return nil, err
			}
			return ecdsa.SignASN1(rand.Reader, ecdsaKey, h.Sum(nil))
		} else {
			return nil, fmt.Errorf("unsupported algorithm %s", alg)
		}
	}, nil
}

func encode(header *jws.Header, key string, c *jws.ClaimSet) (string, error) {
	s, err := signer(header, key)
	if err != nil {
		return "", err
	}
	return jws.EncodeWithSigner(header, c, s)
}

// ParsePublicKey converts the binary contents of a public key file
// to an *rsa.PrivateKey. It detects whether the private key is in a
// PEM container or not. If so, it extracts the the public key
// from PEM container before conversion. It only supports PEM
// containers with no passphrase.
func ParsePublicRSAKey(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("public key should be a PEM or plain PKCS1 or PKIX; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is invalid")
	}
	return parsed, nil
}

func ParsePrivateECDSAKey(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	return x509.ParseECPrivateKey(key)
}
