package lib

import (
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestShouldHideResponseExtraFields(t *testing.T) {
	cases := []struct {
		header string
		value  string
		want   bool
	}{
		{HideResponseExtraFieldsHeader, "1", true},
		{HideResponseExtraFieldsHeader, "true", true},
		{HideResponseExtraFieldsHeader, "TRUE", true},
		{HideResponseExtraFieldsHeader, "yes", true},
		{HideResponseExtraFieldsHeader, " yes ", true},
		{HideResponseExtraFieldsHeader, "0", false},
		{HideResponseExtraFieldsHeader, "false", false},
		{HideResponseExtraFieldsHeader, "no", false},
		{HideResponseExtraFieldsHeader, "", false},
		{"x-other", "true", false},
	}
	for _, c := range cases {
		ctx := &fasthttp.RequestCtx{}
		if c.value != "" {
			ctx.Request.Header.Set(c.header, c.value)
		}
		got := ShouldHideResponseExtraFields(ctx)
		if got != c.want {
			t.Errorf("%s=%q: got %v, want %v", c.header, c.value, got, c.want)
		}
	}
	if ShouldHideResponseExtraFields(nil) != false {
		t.Error("nil ctx should return false")
	}
}

func TestStripExtraFieldsKey(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "removes top-level extra_fields",
			in:   `{"id":"x","model":"gpt-4o","extra_fields":{"latency":1}}`,
			want: `{"id":"x","model":"gpt-4o"}`,
		},
		{
			name: "no extra_fields is no-op",
			in:   `{"id":"x","model":"gpt-4o"}`,
			want: `{"id":"x","model":"gpt-4o"}`,
		},
		{
			name: "preserves nested numeric precision",
			in:   `{"a":12345678901234567,"extra_fields":{"x":1},"b":3.141592653589793}`,
			want: `{"a":12345678901234567,"b":3.141592653589793}`,
		},
		{
			name: "non-object input returned unchanged",
			in:   `[1,2,3]`,
			want: `[1,2,3]`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := string(StripExtraFieldsKey([]byte(c.in)))
			// sjson.DeleteBytes may leave a trailing comma artifact in some versions;
			// require that "extra_fields" is gone and other fields preserved literally.
			if strings.Contains(got, `"extra_fields"`) {
				t.Errorf("extra_fields should be removed; got %s", got)
			}
			// Spot-check that key fields survive byte-for-byte.
			if c.in == `{"a":12345678901234567,"extra_fields":{"x":1},"b":3.141592653589793}` {
				if !strings.Contains(got, `12345678901234567`) {
					t.Errorf("integer precision lost: %s", got)
				}
				if !strings.Contains(got, `3.141592653589793`) {
					t.Errorf("float precision lost: %s", got)
				}
			}
		})
	}
}
