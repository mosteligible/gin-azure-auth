package azauth

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

type OpenidConfig struct {
	TenantId              string
	TokenVersion          int
	AppId                 string
	ConfigUrl             string
	configTimestamp       time.Time
	authorizationEndpoint string
	SigningKeys           map[string]JwtKey
	issuer                string
	tokenEndpoint         string
}

func newOpenidConfig(tenantId, appId, configUrl string, tokenVersion int) OpenidConfig {
	openIdConfig := OpenidConfig{
		TenantId:     tenantId,
		AppId:        appId,
		ConfigUrl:    configUrl,
		TokenVersion: tokenVersion,
	}
	openIdConfig.LoadConfig()
	return openIdConfig
}

func (oidc *OpenidConfig) LoadConfig() error {
	if oidc.configTimestamp.IsZero() {
		oidc.configTimestamp = time.Now()
	}
	refreshTime := time.Now().Add(time.Hour * 24)
	openidConfigLoadSignal := make(chan error)
	if oidc.configTimestamp.Before(refreshTime) {
		go oidc.loadOpenidConfig(openidConfigLoadSignal)
		err := <-openidConfigLoadSignal
		if err != nil {
			return fmt.Errorf("error loading openid config: %s", err.Error())
		}
		defer close(openidConfigLoadSignal)
		oidc.configTimestamp = time.Now()
	}
	log.Println("Settings from Azure AD loaded")
	log.Printf("Authorization endpoint: %s", oidc.authorizationEndpoint)
	log.Printf("Token endpoint:         %s", oidc.tokenEndpoint)
	log.Printf("Issuer:                 %s", oidc.issuer)

	return nil
}

func (oidc *OpenidConfig) loadOpenidConfig(completeSignal chan<- error) {
	openidRespChannel := make(chan ResponseHolder)
	var configUrl string
	if oidc.ConfigUrl != "" {
		configUrl = oidc.ConfigUrl
	} else if oidc.TokenVersion == 2 {
		configUrl = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", oidc.TenantId)
	} else {
		configUrl = fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", oidc.TenantId)
	}

	go SendRequest(configUrl, http.MethodGet, nil, nil, openidRespChannel)
	openidResponse := <-openidRespChannel
	defer close(openidRespChannel)
	defer openidResponse.Resp.Body.Close()
	if openidResponse.Err != nil {
		completeSignal <- openidResponse.Err
		return
	}

	conf, err := ParseToStruct[map[string]interface{}](&openidResponse.Resp.Body)
	if err != nil {
		completeSignal <- err
		return
	}

	jwksUri := conf["jwks_uri"].(string)
	oidc.authorizationEndpoint = conf["authorization_endpoint"].(string)
	oidc.tokenEndpoint = conf["token_endpoint"].(string)
	oidc.issuer = conf["issuer"].(string)

	go SendRequest(jwksUri, http.MethodGet, nil, nil, openidRespChannel)
	openidResponse = <-openidRespChannel
	if openidResponse.Err != nil {
		completeSignal <- openidResponse.Err
		return
	}

	keysResp, err := ParseToStruct[map[string]interface{}](&openidResponse.Resp.Body)
	if err != nil {
		completeSignal <- err
		return
	}
	keys, err := ParseToStruct[[]JwtKey](keysResp["keys"])
	if err != nil {
		completeSignal <- err
	}
	oidc.loadKeys(keys)
	completeSignal <- nil
}

func (oidc *OpenidConfig) loadKeys(keys []JwtKey) {
	oidc.SigningKeys = map[string]JwtKey{}
	for _, k := range keys {
		if k.Use == "sig" {
			oidc.SigningKeys[k.Kid] = k
		}
	}
}
