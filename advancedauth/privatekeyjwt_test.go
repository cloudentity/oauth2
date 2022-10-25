package advancedauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
	"github.com/cloudentity/oauth2/clientcredentials"
	"github.com/cloudentity/oauth2/jws"
	utils "github.com/cloudentity/oauth2/testutils"
)

const (
	privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDYRpq7yP3IaRxFjD9i1VWAFMHgLikJgGQaScg5S9XS3INwYz+E
ZtXrg6++HKyHjqEUeKT+2IZHSJPhOHdKaxh7KCci31MXHtWSG8xMaikKWyLPXjmU
kqONQHOD7XvECqQ8KGkrZ5BTIkVa7KA6aXlYoc3zQpOfbf+wx3/57uuDQQIDAQAB
AoGADKfdCB4T07Vq5Rr23pazQSJ10eOBnT+5G9yzbb7lTUiAHISCRAIshHKZRxuw
cOJExMjmhs8u1F8H4EcIm/82WGsMegCLrS8Y1zW2goiNqIh4QBGHudgvmrXQFz+T
9euhREf4gq7npIHW/ahjCMeEc2Yom4wQC6QJ0bOUu/hiqm0CQQDzIEpFZQnYYMzn
99lk4Qnxh1l0UzTJNNKVidEXi3iHam2ztTkE5mIWlZKHvg5DHzOmvzPKYzFS2YS+
0RACf2/PAkEA47pX1Qc8axoqTBSELA1i3ZKc+qs0mmh2FXcDB2OcpUH00sXLCjGO
r3d57vNRKUYfu7VAQliis8iq5+DPA4sP7wJBAOyLhxd7VZfbnqE2qKGYvcbrzCH8
bogwx45Ml03UGcGO0Asfj8lvqRGWFwnQ5SlzKxraPrZzyeJ01c2dtHjpqksCQCj1
G9Txnzk4FIFoczklEzH8q4UeA7D9trc3l3Ddxo+mZC0Aa/siXKJMX77NPjypIw30
lGEaZfDl128q7LCbczsCQGIBBN0TAwxfYstKeD7g7GXG8yD10LlmB3FCBdQjoBaW
tfeljbt+hNJU/3NIvDhYujEfG2d9cmBZulMRY7gh40Y=
-----END RSA PRIVATE KEY-----`

	publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYRpq7yP3IaRxFjD9i1VWAFMHg
LikJgGQaScg5S9XS3INwYz+EZtXrg6++HKyHjqEUeKT+2IZHSJPhOHdKaxh7KCci
31MXHtWSG8xMaikKWyLPXjmUkqONQHOD7XvECqQ8KGkrZ5BTIkVa7KA6aXlYoc3z
QpOfbf+wx3/57uuDQQIDAQAB
-----END PUBLIC KEY-----`

	privateECDSAKey = `-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQCc6xCaaNyBp2ULknKhpMnvsTfyok5l7VOy7yu8vX5qvKAKBggqhkjO
PQMBB6FEA0IABCI5HIS9PAck6m2w50a9CKPqdoGwIAa2acPB9CkAOb5GIXS69Yh8
kDhNJ1rNy4lUZ8usYgLv+HUIOGFYBFJ10q0=
-----END EC PRIVATE KEY-----`

	publicECDSAKey = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCI5HIS9PAck6m2w50a9CKPqdoGwIAa2acPB9CkAOb5GIXS69Yh8kDhNJ1rNy4lUZ8usYgLv+HUIOGFYBFJ10q0=`
)

func TestPrivateKeyJWT_ClientCredentials(t *testing.T) {
	tcs := []struct {
		title     string
		config    clientcredentials.Config
		publicKey string
	}{
		{
			title: "RSA",
			config: clientcredentials.Config{
				ClientID:  "CLIENT_ID",
				AuthStyle: oauth2.AuthStylePrivateKeyJWT,
				PrivateKeyAuth: advancedauth.PrivateKeyAuth{
					Key: privateKey,
					Alg: "RS256",
				},
				Scopes:         []string{"scope1", "scope2"},
				EndpointParams: url.Values{"audience": {"audience1"}},
			},
			publicKey: publicKey,
		},
		{
			title: "ECDSA",
			config: clientcredentials.Config{
				ClientID:  "CLIENT_ID",
				AuthStyle: oauth2.AuthStylePrivateKeyJWT,
				PrivateKeyAuth: advancedauth.PrivateKeyAuth{
					Key: privateECDSAKey,
					Alg: "ES512",
				},
				Scopes:         []string{"scope1", "scope2"},
				EndpointParams: url.Values{"audience": {"audience1"}},
			},
			publicKey: publicECDSAKey,
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.title, func(tt *testing.T) {
			var serverURL string

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				utils.ExpectURL(tt, r, "/token")
				utils.ExpectHeader(tt, r, "Authorization", "")
				utils.ExpectHeader(tt, r, "Content-Type", "application/x-www-form-urlencoded")
				utils.ExpectFormParam(tt, r, "client_id", "")
				utils.ExpectFormParam(tt, r, "client_secret", "")
				utils.ExpectFormParam(tt, r, "grant_type", "client_credentials")
				utils.ExpectFormParam(tt, r, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

				assertion := r.FormValue("client_assertion")
				if err := advancedauth.Verify(assertion, tc.publicKey); err != nil {
					tt.Error("invalid JWT signature")
				}
				claims, err := jws.Decode(assertion)
				if err != nil {
					tt.Error("could not decode JWT claims")
				}
				utils.RequireStringsEqual(tt, "CLIENT_ID", claims.Iss)
				utils.RequireStringsEqual(tt, "CLIENT_ID", claims.Sub)

				// uuid v4 like
				utils.RequireTrue(tt, len(claims.Jti) == 36)

				utils.RequireTrue(tt, time.Now().Unix() < claims.Exp)
				utils.RequireStringsEqual(tt, serverURL, claims.Aud)

				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
			}))
			serverURL = ts.URL
			defer ts.Close()
			conf := &tc.config
			conf.TokenURL = serverURL + "/token"
			tok, err := conf.Token(context.Background())
			if err != nil {
				tt.Error(err)
			}
			utils.ExpectAccessToken(t, &oauth2.Token{
				AccessToken:  "90d64460d14870c08c81352a05dedd3465940a7c",
				TokenType:    "bearer",
				RefreshToken: "",
				Expiry:       time.Time{},
			}, tok)
		})
	}

}
