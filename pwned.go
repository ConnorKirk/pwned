// Package pwned is a simple wrapper for the Have I been Pwned password API
package pwned

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const (
	baseURL     = "https://api.pwnedpasswords.com"
	passwordURL = baseURL + "/pwnedpassword/"
	rangeURL    = baseURL + "/range/"
)

// CheckWholePassword calls the API and returns the number of times a password has occured
func CheckWholePassword(password string) int {

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

func CheckPasswordFragment(password string) int {
	//hash password
	hashedPassword := hashPassword(password)

	passPrefix, passSuffix := getPassFragments(hashedPassword)

	fmt.Printf("%s\n", passPrefix)
	fmt.Printf("length: %v\n", len(passPrefix))
	//send to api
	URL := strings.Join([]string{rangeURL, string(passPrefix)}, "")

	resp, err := http.Get(URL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	//parse response
	body, err := ioutil.ReadAll((resp.Body))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(body))

	lines := bytes.Split(body, []byte("\n"))
	return findPassCount(lines, passSuffix)
}

func hashPassword(password string) []byte {
	hasher := sha1.New()
	hasher.Write([]byte(password))

	return hasher.Sum(nil)
}

func getPassFragments(hashedPassword []byte) (passPrefix, passSuffix string) {
	hexHash := hex.EncodeToString(hashedPassword)

	prefix := hexHash[:5]
	suffix := hexHash[5:]
	return prefix, suffix
}

func parseLine(line []byte) ([]byte, int) {
	s := bytes.Split(line, []byte(":"))
	suffix := s[0]

	//Remove \r line return character if present
	c := bytes.Replace(s[1], []byte("\r"), []byte(""), 1)
	count, err := strconv.Atoi(string(c))
	if err != nil {
		panic(err)
	}
	return suffix, count
}

func findPassCount(lines [][]byte, targetSuffix string) int {
	var ret int
	var found bool
	for _, line := range lines {
		suffix, count := parseLine(line)
		if string(suffix) == strings.ToUpper(targetSuffix) {
			ret = count
			found = true
			break
		}
	}
	if !found {
		panic("Not found" + targetSuffix)
	}
	return ret
}
