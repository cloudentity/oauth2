package advancedauth

import (
	"net/url"
	"time"

	"github.com/cloudentity/oauth2"
)

type PrivateKeyAuth struct {
	Key   string
	KeyID string
	Alg   string
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
