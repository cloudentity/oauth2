package advancedauth

import (
	"net/url"
	"time"

	"github.com/cloudentity/oauth2"
)

type Algorithm string

const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"

	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
)

type PrivateKeyAuth struct {
	Key   string
	KeyID string
	Alg   Algorithm
	Exp   time.Duration
}

type Config struct {
	AuthStyle      oauth2.AuthStyle
	ClientID       string
	PrivateKeyAuth PrivateKeyAuth
	TokenURL       string
}

func UrlValuesFromConfig(v url.Values, c Config) (url.Values, error) {
	if c.AuthStyle == oauth2.AuthStylePrivateKeyJWT {
		var err error
		jwtVals, err := privateKeyJWTAssertionVals(c)
		if err != nil {
			return nil, err
		}
		for key, vals := range jwtVals {
			for _, val := range vals {
				v.Set(key, val)
			}
		}
	}
	return v, nil
}
