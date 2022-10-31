# OAuth2 for Go - extended with advanced authentication

This repo is a drop-in replacement of `golang.org/x/oauth2`

It extends the original library with additional authentication methods:

- private_key_jwt

## Installation

When using go modules you can run:

`go mod edit -replace golang.org/x/oauth2 github.com/cloudentity/oauth2`

## Usage

When using any of the originally supported authentication methods, there's no need to change anything.
This library can be used as a drop-in replacement.

For new authentication methods see:

### Private Key JWT

#### Client credentials

```go
import (
	"context"
	"time"

	"github.com/cloudentity/oauth2/advancedauth"
	"github.com/cloudentity/oauth2/clientcredentials"
)
```

```go
    cfg := clientcredentials.Config{
        ClientID: "your client id",
    	PrivateKeyAuth: advancedauth.PrivateKeyAuth{
    		Key:   "your PEM encoded private key",
    		Alg:   advancedauth.RS256,
    		Exp:   30 * time.Second,
    	},
    }

    token, err := cfg.Token(context.Background())
```

## Implementation

This fork tries to limit changes to the original codebase to the minimum.
All the new major changes are implemented in the `advancedauth` package.
