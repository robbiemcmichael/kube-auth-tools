package connector

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

func Dex(loginURI *url.URL, username string, password string) (*url.URL, error) {
	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Second * 10,
	}

	log.Debugln("Posting credentials to", loginURI)
	credentials := url.Values{"login": {username}, "password": {password}}
	loginResponse, err := noRedirect.PostForm(loginURI.String(), credentials)
	if err != nil {
		return nil, fmt.Errorf("Failed to post credentials: %s", err)
	}

	approvalURI, err := loginURI.Parse(loginResponse.Header.Get("Location"))
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch approval URI: %s", err)
	}
	log.Debugln("Received approval URI", approvalURI)

	if approvalURI.String() == loginURI.String() {
		// Giving specific context to this error requires parsing the response body
		return nil, fmt.Errorf("Possibly incorrect username/password, invalid redirect URI or other error")
	}

	reqID := approvalURI.Query().Get("req")
	if reqID == "" {
		return nil, fmt.Errorf("Could not extract request ID from %s", approvalURI)
	}

	log.Debugln("Posting approvol of scopes to", approvalURI)
	approvalValues := url.Values{"req": {reqID}, "approval": {"approve"}}
	approvalResponse, err := noRedirect.PostForm(approvalURI.String(), approvalValues)
	if err != nil {
		return nil, fmt.Errorf("Failed to post approval: %s", err)
	}

	callbackURI, err := approvalURI.Parse(approvalResponse.Header.Get("Location"))
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch callback URI: %s", err)
	}
	log.Debugln("Received callback URI", callbackURI)

	return callbackURI, nil
}
