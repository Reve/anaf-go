package anaf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type AnafAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
	TokenURL     string
	httpClient   *http.Client
}

func NewAnafAuth(clientID, clientSecret, redirectURI string) *AnafAuth {
	return &AnafAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		AuthURL:      "https://logincert.anaf.ro/anaf-oauth2/v1/authorize",
		TokenURL:     "https://logincert.anaf.ro/anaf-oauth2/v1/token",
		httpClient:   http.DefaultClient,
	}
}

func (a *AnafAuth) SetAuthURL(u string) {
	a.AuthURL = u
}

func (a *AnafAuth) SetTokenURL(u string) {
	a.TokenURL = u
}

func (a *AnafAuth) GetAuthURL() string {
	// Build the query
	params := url.Values{}
	params.Set("client_id", a.ClientID)
	params.Set("client_secret", a.ClientSecret)
	params.Set("response_type", "code")
	params.Set("token_content_type", "jwt")
	params.Set("redirect_uri", a.RedirectURI)

	return fmt.Sprintf("%s?%s", a.AuthURL, params.Encode())
}

func (a *AnafAuth) GetAnafToken(ctx context.Context, code string) (map[string]interface{}, error) {
	if code == "" {
		return nil, errors.New("no code provided")
	}

	data := url.Values{}
	data.Set("client_id", a.ClientID)
	data.Set("client_secret", a.ClientSecret)
	data.Set("grant_type", "authorization_code")
	data.Set("token_content_type", "jwt")
	data.Set("code", code)
	data.Set("redirect_uri", a.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, &AnafResponseError{Msg: fmt.Sprintf("error getting token: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &AnafResponseError{Msg: "error getting token", Code: resp.StatusCode}
	}

	var resObj map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&resObj); err != nil {
		return nil, err
	}

	return resObj, nil
}

func (a *AnafAuth) RefreshAnafToken(ctx context.Context, refreshToken string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("client_id", a.ClientID)
	data.Set("client_secret", a.ClientSecret)
	data.Set("grant_type", "refresh_token")
	data.Set("token_content_type", "jwt")
	data.Set("refresh_token", refreshToken)
	data.Set("redirect_uri", a.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, &AnafResponseError{Msg: fmt.Sprintf("error refreshing token: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &AnafResponseError{Msg: "error refreshing token", Code: resp.StatusCode}
	}

	var resObj map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&resObj); err != nil {
		return nil, err
	}

	return resObj, nil
}
