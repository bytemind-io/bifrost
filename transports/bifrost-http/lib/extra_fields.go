package lib

import (
	"strings"

	"github.com/tidwall/sjson"
	"github.com/valyala/fasthttp"
)

// HideResponseExtraFieldsHeader is a request header clients can set to suppress
// the `extra_fields` key from JSON responses. Accepts "1", "true", or "yes"
// (case-insensitive).
const HideResponseExtraFieldsHeader = "x-bf-hide-response-extra-fields"

// ShouldHideResponseExtraFields reports whether the caller asked us to strip
// the top-level `extra_fields` key from the JSON response body via the
// x-bf-hide-response-extra-fields request header.
func ShouldHideResponseExtraFields(ctx *fasthttp.RequestCtx) bool {
	if ctx == nil {
		return false
	}
	v := strings.TrimSpace(string(ctx.Request.Header.Peek(HideResponseExtraFieldsHeader)))
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// StripExtraFieldsKey removes the top-level "extra_fields" key from the supplied
// JSON object bytes. Returns the input unchanged on failure — callers should
// treat the function as best-effort.
func StripExtraFieldsKey(body []byte) []byte {
	out, err := sjson.DeleteBytes(body, "extra_fields")
	if err != nil {
		return body
	}
	return out
}
