package advancedauth

import (
	"net/url"

	"github.com/cloudentity/oauth2"
)

type Config struct {
	AuthStyle  oauth2.AuthStyle
	ClientID   string
	PrivateKey string
	TokenURL   string
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
