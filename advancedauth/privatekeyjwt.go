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

type PrivateKeyAuth struct {
	Key string
	Alg Algorithm
	Exp time.Duration
}

func privateKeyJWTAssertionVals(c Config) (url.Values, error) {
	var (
		err       error
		assertion string
		id        uuid.UUID
		key       interface{}
		token     *jwt.Token
		exp       time.Duration
		alg       Algorithm
	)

	if id, err = uuid.NewUUID(); err != nil {
		return url.Values{}, err
	}
	jti := id.String()

	exp = c.PrivateKeyAuth.Exp
	if exp == 0*time.Second {
		exp = 30 * time.Second
	}

	claims := &jwt.RegisteredClaims{
		Issuer:    c.ClientID,
		Subject:   c.ClientID,
		Audience:  []string{strings.TrimSuffix(c.TokenURL, "/token")},
		ID:        jti,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(exp)),
	}

	alg = c.PrivateKeyAuth.Alg
	if alg == "" {
		alg = RS256
	}

	switch alg {
	case RS256, RS384, RS512:
		if key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(c.PrivateKeyAuth.Key)); err != nil {
			return url.Values{}, fmt.Errorf("could not parse private key from PEM %s", alg)
		}
	case ES256, ES384, ES512:
		if key, err = jwt.ParseECPrivateKeyFromPEM([]byte(c.PrivateKeyAuth.Key)); err != nil {
			return url.Values{}, fmt.Errorf("could not parse private key from PEM %s", alg)
		}
	default:
		return url.Values{}, fmt.Errorf("unsupported algorithm %s", alg)
	}

	token = jwt.NewWithClaims(jwt.GetSigningMethod(string(alg)), claims)

	if assertion, err = token.SignedString(key); err != nil {
		return url.Values{}, err
	}

	return url.Values{
		"client_assertion":      []string{assertion},
		"client_assertion_type": []string{privateKeyJWTAssertionType},
	}, nil
}
