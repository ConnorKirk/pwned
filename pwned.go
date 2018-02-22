// Package pwned is a simple wrapper for the Have I been Pwned password API
package pwned

import (
	"encoding/binary"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	baseURL     = "https://api.pwnedpasswords.com"
	passwordURL = baseURL + "/pwnedpassword/"
)

// CheckPassword calls the API and returns the number of times a password has occured
func CheckPassword(password string) int {

	//form string
	URL := strings.Join([]string{passwordURL, password}, "")

	//call URL
	resp, err := http.Get(URL)

	if err != nil {
		log.Fatalf("Can't call API: %v", err)
	}

	//Parse body
	count, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	// Convert to int
	if err != nil {
		log.Fatal(err)
	}

	convertedInt := binary.BigEndian.Uint16(count)

	return int(convertedInt)

}
