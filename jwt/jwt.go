package jwt

import (
	"encoding/base64"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func IsValidJWT(encodedToken string) bool {
	token, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		return false
	}

	p := gojwt.NewParser()
	_, _, err = p.ParseUnverified(string(token), gojwt.MapClaims{})

	return err == nil
}
