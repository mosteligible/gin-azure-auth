package azauth

import (
	"errors"
	"log"

	"github.com/golang-jwt/jwt/v5"
)

type UserClaims struct {
	Id    string `json:"id,omitempty"`
	Oid   string `json:"oid,omitempty"`
	Aud   string `json:"aud,omitempty"`
	AppId string `json:"appid,omitempty"`
	Name  string `json:"name,omitempty"`
	Email string `json:"unique_name,omitempty"`
	jwt.RegisteredClaims
}

type JwtKey struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type Authorizer struct {
	OpenidConfig OpenidConfig
	AppId        string
	TenantId     string
}

func newAuthorizer(tenantId string, appId string, tokenVersion int) *Authorizer {
	authorizer := &Authorizer{AppId: appId, TenantId: tenantId}
	authorizer.OpenidConfig = newOpenidConfig(tenantId, appId, "", tokenVersion)
	return authorizer
}

func (auth *Authorizer) ParseAccessToken(accessToken string) (*UserClaims, error) {
	var uc UserClaims
	auth.OpenidConfig.LoadConfig()
	jwtParser := jwt.Parser{}
	token, _, err := jwtParser.ParseUnverified(accessToken, &uc)
	if err != nil {
		log.Printf("Error unverified parsing of token")
		return nil, errors.New("Invalid token, unable to parse it!")
	}
	claims := token.Claims.(*UserClaims)
	kid := token.Header["kid"].(string)
	audience := claims.Aud
	key, ok := auth.OpenidConfig.SigningKeys[kid]
	if !ok {
		log.Printf("Invalid token, could not find public key. Found kid: <%s>", kid)
		return nil, errors.New("Invalid token!")
	}

	if audience != auth.AppId {
		return nil, errors.New("Invalid token!")
	}
	_, err = jwtParser.Parse(accessToken, func(tok *jwt.Token) (interface{}, error) {
		return []byte(key.X5c[0]), nil
	})
	if err != nil {
		return nil, errors.New("Invalid token!")
	}

	return claims, nil
}

var oauth Authorizer
