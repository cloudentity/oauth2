package testutils

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/cloudentity/oauth2"
)

func ExpectHeader(t *testing.T, r *http.Request, header string, expected string) {
	actual := r.Header.Get(header)
	if actual != expected {
		t.Errorf("Expected header %s to be %s, got %s", header, expected, actual)
	}
}

func ExpectURL(t *testing.T, r *http.Request, expected string) {
	actual := r.URL.String()
	if actual != expected {
		t.Errorf("Expected url to be %s, got %s", expected, actual)
	}
}

func ExpectBody(t *testing.T, r *http.Request, expected string) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		r.Body.Close()
	}
	if err != nil {
		t.Errorf("failed reading request body: %s.", err)
	}
	actual := string(body)
	if actual != expected {
		t.Errorf("Expected body to be %s, got %s", expected, actual)
	}
}

func ExpectAccessToken(t *testing.T, expected *oauth2.Token, actual *oauth2.Token) {
	if !actual.Valid() {
		t.Fatalf("token invalid. got: %#v", actual)
	}
	if actual.AccessToken != expected.AccessToken {
		t.Errorf("Access token = %q; want %q", actual.AccessToken, expected.AccessToken)
	}
	if actual.TokenType != expected.TokenType {
		t.Errorf("token type = %q; want %q", actual.TokenType, expected.TokenType)
	}
}

func ExpectFormParam(t *testing.T, r *http.Request, param string, expected string) {
	actual := r.FormValue(param)
	if actual != expected {
		t.Errorf("Expected form param %s to be %s, got %s", param, expected, actual)
	}
}

func RequireStringsEqual(t *testing.T, expected string, actual string) {
	if actual != expected {
		t.Errorf("Expected %s and %s to be equal", expected, actual)
	}
}

func RequireStringNonEmpty(t *testing.T, actual string) {
	if actual == "" {
		t.Errorf("Expected not empty %s", actual)
	}
}

func RequireTrue(t *testing.T, actual bool) {
	if !actual {
		t.Errorf("Expected true %t", actual)
	}
}