package pwned

import (
	"fmt"
	"reflect"
	"testing"
)

const checkMark = "\u2713"
const ballotX = "\u2717"
const examplePass = "password1"

//TestCheckPassword validates that the API is working
func TestCheckWholePassword(t *testing.T) {
	t.Logf("Making API call with example password: %v", examplePass)
	response := CheckWholePassword(examplePass)
	t.Logf("Recieved %v, %v", response, checkMark)
}

func TestCheckPasswordFragment(t *testing.T) {
	wantCount := 2310111
	t.Logf("Marking API call with example password: %v", examplePass)
	count := CheckPasswordFragment(examplePass)
	t.Logf("Recieved %v", checkMark)
	if count != wantCount {
		t.Errorf("got %v, wanted %v", count, wantCount)
	}
}

func TestHashPassword(t *testing.T) {
	output := hashPassword(examplePass)
	t.Logf("%x\n%v", string(output), output)
}

func TestParseLine(t *testing.T) {
	inputString := []byte("00CBB2A6F377FACA93FA20D1A7D4D68EF9C:1\r")
	suffix, count := parseLine(inputString)
	fmt.Println(string(suffix), count)
}

func Test_getPassFragments(t *testing.T) {
	type args struct {
		hashedPassword []byte
	}
	tests := []struct {
		name           string
		args           args
		wantPassPrefix string
		wantPassSuffix string
	}{
		{
			name:           "1",
			args:           args{hashPassword(examplePass)},
			wantPassPrefix: "e38ad",
			wantPassSuffix: "214943daad1d64c102faec29de4afe9da3d",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPassPrefix, gotPassSuffix := getPassFragments(tt.args.hashedPassword)
			if !reflect.DeepEqual(gotPassPrefix, tt.wantPassPrefix) {
				t.Errorf("getPassFragments() gotPassPrefix = %v, want %v", gotPassPrefix, tt.wantPassPrefix)
			}
			if !reflect.DeepEqual(gotPassSuffix, tt.wantPassSuffix) {
				t.Errorf("getPassFragments() gotPassSuffix = %v, want %v", gotPassSuffix, tt.wantPassSuffix)
			}
		})
	}
}
