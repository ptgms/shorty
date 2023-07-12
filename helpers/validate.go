package helpers

import (
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"strconv"
)

func IsTokenValid(token *oauth2.Token, config Configuration, oauthConfig *oauth2.Config) (bool, AuthUser) {
	client := oauthConfig.Client(context.Background(), token)
	switch config.OAuth.Type {
	case "discord":
		return isDiscordTokenValid(client)
	case "google":
		return isGoogleTokenValid(client)
	case "github":
		return isGithubTokenValid(client)
	default:
		return false, AuthUser{}
	}
}

func isGithubTokenValid(client *http.Client) (bool, AuthUser) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return false, AuthUser{}
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var result map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false, AuthUser{}
	}

	authUser := AuthUser{
		Username: result["login"].(string),
		ID:       strconv.FormatFloat(result["id"].(float64), 'f', 0, 64),
	}

	return resp.StatusCode == http.StatusOK, authUser
}

func isDiscordTokenValid(client *http.Client) (bool, AuthUser) {
	resp, err := client.Get("https://discord.com/api/users/@me")
	if err != nil {
		return false, AuthUser{}
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var result map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false, AuthUser{}
	}

	authUser := AuthUser{
		Username: result["username"].(string),
		ID:       result["id"].(string),
	}

	return resp.StatusCode == http.StatusOK, authUser
}

func isGoogleTokenValid(client *http.Client) (bool, AuthUser) {
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return false, AuthUser{}
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var result map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false, AuthUser{}
	}

	authUser := AuthUser{
		Username: result["name"].(string),
		ID:       result["id"].(string),
	}

	return resp.StatusCode == http.StatusOK, authUser
}
