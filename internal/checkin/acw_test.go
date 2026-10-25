package checkin

import (
	"strings"
	"testing"
)

func TestACWKnownVectorAndClosedTemplate(t *testing.T) {
	html := acwFixture(t)
	value, ok := SolveACW(html)
	if !ok || value != "699dbedad126579b6bc0ebb91eaae8d7af3548b5" {
		t.Fatalf("known vector %q/%v", value, ok)
	}
	arg := "B8B78DDA1D5CD2598AAEE9DD6975913AA490BAE3"
	zero := strings.ReplaceAll(html, arg, strings.Repeat("0", 40))
	if value, ok := SolveACW(zero); !ok || value != "3000176000856006061501533003690027800375" {
		t.Fatalf("variable arg failed %q/%v", value, ok)
	}
	for _, bad := range []string{html + "<script>evil()</script>", strings.Replace(html, "function a0i()", "function unknown()", 1), strings.ReplaceAll(html, arg, strings.Repeat("F", 39)), strings.Replace(html, "acw_sc__v2", "other_cookie", 1), strings.Repeat("x", 20000) + html, `<html><script>var arg1='` + arg + `';document.cookie='acw_sc__v2=x';</script></html>`, strings.Replace(html, "</script>", ";fetch('/api/user/sign_in',{method:'POST'});</script>", 1)} {
		if _, ok := SolveACW(bad); ok {
			t.Fatal("accepted modified challenge")
		}
	}
}
