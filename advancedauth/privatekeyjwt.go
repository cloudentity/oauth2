package advancedauth

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const privateKeyJWTAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func privateKeyJWTAssertionVals(c Config) (url.Values, error) {
	var (
		err       error
		assertion string
		id        uuid.UUID
		key       interface{}
		token     *jwt.Token
	)

	if id, err = uuid.NewUUID(); err != nil {
		return url.Values{}, err
	}
	jti := id.String()

	claims := &jwt.RegisteredClaims{
		Issuer:    c.ClientID,
		Subject:   c.ClientID,
		Audience:  []string{strings.TrimSuffix(c.TokenURL, "/token")},
		ID:        jti,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)), // TODO configurable?
	}

	switch c.PrivateKeyAuth.Alg {
	case "RS256", "RS384", "RS512":
		key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(c.PrivateKeyAuth.Key))
		if err != nil {
			return url.Values{}, fmt.Errorf("could not parse private key from PEM %s", c.PrivateKeyAuth.Alg)
		}
	case "ES256", "ES384", "ES512":
		key, err = jwt.ParseECPrivateKeyFromPEM([]byte(c.PrivateKeyAuth.Key))
		if err != nil {

			return url.Values{}, fmt.Errorf("could not parse private key from PEM %s", c.PrivateKeyAuth.Alg)
		}
	default:
		return url.Values{}, fmt.Errorf("unsupported algorithm %s", c.PrivateKeyAuth.Alg)
	}

	token = jwt.NewWithClaims(jwt.GetSigningMethod(c.PrivateKeyAuth.Alg), claims)

	assertion, err = token.SignedString(key)
	if err != nil {

		return url.Values{}, err
	}

	return url.Values{
		"client_assertion":      []string{assertion},
		"client_assertion_type": []string{privateKeyJWTAssertionType},
	}, nil
}
