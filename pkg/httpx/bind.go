package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"godigi/pkg/apperr"
)

var validate = newValidator()

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterTagNameFunc(func(f reflect.StructField) string {
		name := strings.SplitN(f.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	return v
}

// BindJSON decodes exactly one JSON object into dst and validates it.
//
// Unknown fields are rejected rather than ignored: a client sending
// {"status":"active"} to a profile endpoint gets a 400 naming the field,
// instead of a 200 that silently did something different from what it asked.
func BindJSON(c *gin.Context, dst any) error {
	if c.ContentType() != "application/json" {
		return apperr.New(http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
	}
	if c.Request.Body == nil {
		return apperr.BadRequest("INVALID_JSON", "request body is required")
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apperr.BadRequest("INVALID_JSON", "request body must contain a single JSON object")
	}
	if err := validate.Struct(dst); err != nil {
		return validationError(err)
	}
	return nil
}

func decodeError(err error) error {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var maxErr *http.MaxBytesError
	switch {
	case errors.Is(err, io.EOF):
		return apperr.BadRequest("INVALID_JSON", "request body is required")
	case errors.Is(err, io.ErrUnexpectedEOF):
		return apperr.BadRequest("INVALID_JSON", "request body is not valid JSON")
	case errors.As(err, &syntaxErr):
		return apperr.BadRequest("INVALID_JSON", fmt.Sprintf("request body is not valid JSON (at byte %d)", syntaxErr.Offset))
	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			return apperr.BadRequest("INVALID_JSON", "request body must be a JSON object")
		}
		return apperr.Field(field, "must be a "+jsonType(typeErr.Type.Kind()))
	case errors.As(err, &maxErr):
		return apperr.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "request body is too large")
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return apperr.Field(field, "unknown field or field cannot be modified")
	default:
		return apperr.BadRequest("INVALID_JSON", "request body is not valid JSON")
	}
}

func jsonType(k reflect.Kind) string {
	switch k {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Float64, reflect.Float32:
		return "number"
	default:
		return "valid value"
	}
}

func validationError(err error) error {
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		return apperr.Internal(err)
	}
	details := make([]apperr.FieldError, 0, len(verrs))
	for _, fe := range verrs {
		details = append(details, apperr.FieldError{Field: fe.Field(), Message: message(fe)})
	}
	return apperr.Validation(details...)
}

func message(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "is required"
	case "email":
		return "must be a valid email address"
	case "min":
		return "must be at least " + fe.Param() + " characters"
	case "max":
		return "must be at most " + fe.Param() + " characters"
	case "len":
		return "must be exactly " + fe.Param() + " characters"
	case "numeric":
		return "must contain only digits"
	case "e164":
		return "must be a phone number in E.164 format, e.g. +6281234567890"
	default:
		return "is invalid"
	}
}
