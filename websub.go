package websub

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// WebSub implement http.Handler interface
type WebSub struct {
	verifyToken string
	callback    func(body []byte) (int, error)
}

func (ws WebSub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		status, err := ws.get(w, r)
		w.WriteHeader(status)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	case "POST":
		status, err := ws.post(r)
		w.WriteHeader(status)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleFunc registers the handler for the given pattern
func HandleFunc(pattern string, callback func(body []byte) (int, error), verifyToken string) {
	http.Handle(pattern, WebSub{verifyToken: verifyToken, callback: callback})
}

func (ws WebSub) get(w http.ResponseWriter, req *http.Request) (int, error) {

	if hubverifytoken := req.FormValue("hub.verify_token"); hubverifytoken != ws.verifyToken {
		return http.StatusUnauthorized, fmt.Errorf("Wrong verify_token: %s != %s", hubverifytoken, ws.verifyToken)
	}

	hubmode := req.FormValue("hub.mode")
	switch hubmode {
	case "subscribe":
		fallthrough
	case "unsubscribe":
		w.Header().Set("Content-Type", "text/plain")
		hubchallenge := req.FormValue("hub.challenge")
		if _, err := w.Write([]byte(hubchallenge)); err != nil {
			return http.StatusInternalServerError, errors.Wrap(err, "Write error on subscribe/Unsubscribe")
		}
		return http.StatusOK, nil
	default:
		return http.StatusForbidden, fmt.Errorf("hub.mode NG %s %s", hubmode, "StatusForbidden")
	}
}

func (ws WebSub) post(req *http.Request) (int, error) {

	xhubsignature := strings.SplitN(req.Header.Get("X-Hub-Signature"), `=`, 2)

	if len(xhubsignature) != 2 {
		return http.StatusForbidden, errors.New("No Hash/StatusForbidden")
	}

	var mac hash.Hash
	switch xhubsignature[0] {
	case `sha1`:
		mac = hmac.New(sha1.New, []byte(ws.verifyToken))
	case `sha256`:
		mac = hmac.New(sha256.New, []byte(ws.verifyToken))
	case `sha384`:
		mac = hmac.New(sha512.New384, []byte(ws.verifyToken))
	case `sha512`:
		mac = hmac.New(sha512.New, []byte(ws.verifyToken))
	default:
		return http.StatusInternalServerError, fmt.Errorf(`Unknown signature type %s`, xhubsignature[0])
	}

	body, err := ioutil.ReadAll(io.TeeReader(req.Body, mac))
	if err != nil {
		return http.StatusNotFound, errors.Wrap(err, "Error on ReadAll")
	}

	expectedMAC := mac.Sum(nil)

	actual := make([]byte, 20)
	_, err = hex.Decode(actual, []byte(xhubsignature[1]))
	if err != nil {
		return http.StatusInternalServerError, errors.Wrap(err, `X-Hub-Signature: hex.Decode`)
	}
	if !hmac.Equal(expectedMAC, actual) {
		return http.StatusForbidden, fmt.Errorf("Hash NG/StatusForbidden/X-Hub-Signature: %s", req.Header.Get("X-Hub-Signature"))
	}

	status, err := ws.callback(body)
	return status, errors.Wrap(err, "Error on WebSub callback")
}
