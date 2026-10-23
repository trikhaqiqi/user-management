package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"godigi/pkg/apperr"
)

type profileReq struct {
	Name  *string `json:"name" validate:"omitempty,max=5"`
	Email string  `json:"email" validate:"omitempty,email"`
}

func bind(t *testing.T, contentType, body string) error {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", contentType)
	var dst profileReq
	return BindJSON(c, &dst)
}

func code(err error) string {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		if len(ae.Details) > 0 {
			return ae.Code + ":" + ae.Details[0].Field
		}
		return ae.Code
	}
	return ""
}

func TestBindJSON(t *testing.T) {
	cases := []struct {
		ct, body, want string
	}{
		{"application/json", `{"name":"abc"}`, ""},
		{"application/json", `{"status":"active"}`, "VALIDATION_ERROR:status"},
		{"application/json", `{"name":"toolong"}`, "VALIDATION_ERROR:name"},
		{"application/json", `{"email":"nope"}`, "VALIDATION_ERROR:email"},
		{"application/json", `{"name":1}`, "VALIDATION_ERROR:name"},
		{"application/json", `{"name":"a"}{"name":"b"}`, "INVALID_JSON"},
		{"application/json", `{`, "INVALID_JSON"},
		{"application/json", ``, "INVALID_JSON"},
		{"text/plain", `{}`, "UNSUPPORTED_MEDIA_TYPE"},
	}
	for _, tc := range cases {
		if got := code(bind(t, tc.ct, tc.body)); got != tc.want {
			t.Errorf("%s %q: got %q want %q", tc.ct, tc.body, got, tc.want)
		}
	}
}
