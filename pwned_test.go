package pwned

import (
	"testing"
)

const checkMark = "\u2713"
const ballotX = "\u2717"

//TestCheckPassword validates that the API is working
func TestCheckPassword(t *testing.T) {

	examplePass := "Password"
	//statusCode := 200

	t.Logf("Making API call with example password: %v", examplePass)
	response := CheckPassword(examplePass)
	t.Logf("Recieved %v, %v", response, checkMark)
}
