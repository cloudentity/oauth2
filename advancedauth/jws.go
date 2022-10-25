package advancedauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudentity/oauth2/internal"
	"github.com/cloudentity/oauth2/jws"
)

func signer(header *jws.Header, key string) (func(data []byte) (sig []byte, err error), error) {
	hash, alg, err := hashAlg(header)
	if err != nil {
		return nil, err
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

func hashAlg(header *jws.Header) (crypto.Hash, string, error) {
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
		return 0, "", fmt.Errorf("unsupported algorithm %s", a)
	}

	return hash, alg, nil

}

func encode(header *jws.Header, key string, c *jws.ClaimSet) (string, error) {
	s, err := signer(header, key)
	if err != nil {
		return "", err
	}
	return jws.EncodeWithSigner(header, c, s)
}

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

func ParsePublicECDSAKey(key []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}

	pk, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pk.(*ecdsa.PublicKey)

	if !ok {
		return nil, errors.New("jws: could not parse ecdsa public key")
	}

	return publicKey, nil
}

// Verify tests whether the provided JWT token's signature was produced by the private key
// associated with the supplied public key.
func Verify(token string, publicKey string) error {
	var (
		hash            crypto.Hash
		alg             string
		err             error
		headerString    []byte
		signatureString []byte
		header          = jws.Header{}
	)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("jws: invalid token received, token must have 3 parts")
	}

	signedContent := parts[0] + "." + parts[1]
	headerString, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	signatureString, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(headerString), &header)
	if err != nil {
		return err
	}

	hash, alg, err = hashAlg(&header)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write([]byte(signedContent))

	if alg == "RSA" {
		rsaKey, err := ParsePublicRSAKey([]byte(publicKey))
		if err != nil {
			return err
		}
		return rsa.VerifyPKCS1v15(rsaKey, hash, h.Sum(nil), signatureString)
	} else if alg == "ECDSA" {
		ecdsaKey, err := ParsePublicECDSAKey([]byte(publicKey))
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(ecdsaKey, h.Sum(nil), signatureString) {
			return errors.New("invalid token")
		}
		return nil
	} else {
		return fmt.Errorf("unsupported algorithm %s", alg)
	}
}
