package advancedauth

import (
	"net/url"
	"strings"
	"time"

	"github.com/cloudentity/oauth2/jws"
	"github.com/google/uuid"
)

const privateKeyJWTAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func privateKeyJWTAssertionVals(c Config) (url.Values, error) {
	var (
		err       error
		assertion string
		id        uuid.UUID
	)

	if id, err = uuid.NewUUID(); err != nil {
		return url.Values{}, err
	}

	jti := id.String()

	claims := &jws.ClaimSet{
		Iss: c.ClientID,
		Sub: c.ClientID,
		Aud: strings.TrimSuffix(c.TokenURL, "/token"),
		Jti: jti,
		Exp: time.Now().Add(30 * time.Second).Unix(), // TODO configurable?
	}

	header := &jws.Header{
		Algorithm: c.PrivateKeyAuth.Alg,
		Typ:       "JWT",
		KeyID:     c.PrivateKeyAuth.KeyID,
	}

	if assertion, err = encode(header, c.PrivateKeyAuth.Key, claims); err != nil {
		return url.Values{}, err
	}

	return url.Values{
		"client_assertion":      []string{assertion},
		"client_assertion_type": []string{privateKeyJWTAssertionType},
	}, nil
}
