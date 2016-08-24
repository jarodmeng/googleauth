// Package googleauth, given a client id and secret, gets/stores/refreshes an
// OAuth2.0 token with Google. It uses the context/config/token to create an
// http client ready to be passed to New() to create API service instances.
package googleauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func tokenCacheFile(tokenFile string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	tokenCacheDir := filepath.Join(usr.HomeDir, ".credentials")
	os.MkdirAll(tokenCacheDir, 0700)

	return filepath.Join(tokenCacheDir, url.QueryEscape(tokenFile)), nil
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		return nil, err
	}

	t := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(t)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func getTokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, err
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	return tok, nil
}

func saveToken(file string, token *oauth2.Token) error {
	f, err := os.Create(file)
	defer f.Close()
	if err != nil {
		return err
	}

	err = json.NewEncoder(f).Encode(token)
	if err != nil {
		return err
	}

	return nil
}

func getClient(ctx context.Context, config *oauth2.Config, tokenFile string) (*http.Client, error) {
	cacheFile, err := tokenCacheFile(tokenFile)
	if err != nil {
		return nil, err
	}

	tok, err := tokenFromFile(cacheFile)
	if err != nil {
		tok, err = getTokenFromWeb(config)
		if err != nil {
			return nil, err
		}
		err = saveToken(cacheFile, tok)
		if err != nil {
			return nil, err
		}
	}

	return config.Client(ctx, tok), nil
}

// CreateClient uses a client ID and secret file, a token file and a scope
// string to create an HTTP client. The HTTP client can be passed to New()
// function of Google client libraries to create an API service instance.
func CreateClient(secretFile string, tokenFile string, scope string) (*http.Client, error) {
	ctx := context.Background()

	b, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return nil, err
	}

	config, err := google.ConfigFromJSON(b, scope)
	if err != nil {
		return nil, err
	}

	client, err := getClient(ctx, config, tokenFile)
	if err != nil {
		return nil, err
	}

	return client, nil
}
