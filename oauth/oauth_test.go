package oauth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	fmt.Println("about to start main test")
	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicFalse(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}

	assert.False(t, IsPublic(&request))

	request.Header.Add("X-Public", "true")
	assert.True(t, IsPublic(&request))
}

func TestGetCallerIdNilRequest(t *testing.T) {

}

func TestGetCallerInvalidCallerFormat(t *testing.T) {

}

func TestGetCallerNoError(t *testing.T) {

}