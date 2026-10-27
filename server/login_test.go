package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
)

// setupLogin configures a keystore at keystore.example.com with no one logged
// in. CertKit redeems every code for alice@example.com, and the returned
// slice records each "code verifier" redeemed.
func setupLogin(t *testing.T) *[]string {
	t.Helper()
	prevConfig, prevRedeem, prevSessions := config.CurrentConfig, redeemLogin, sessions
	t.Cleanup(func() {
		config.CurrentConfig = prevConfig
		redeemLogin = prevRedeem
		sessions = prevSessions
	})

	config.CurrentConfig = config.Config{
		CertkitBaseUrl: "https://app.certkit.test/",
		Keystore:       &config.KeystoreInfo{Id: "ks1", Host: "keystore.example.com", Port: "443"},
	}
	sessions = map[string]time.Time{}
	redeemed := []string{}
	redeemLogin = func(code, verifier string) (*api.RedeemLoginResponse, error) {
		redeemed = append(redeemed, code+" "+verifier)
		return &api.RedeemLoginResponse{Email: "alice@example.com"}, nil
	}
	return &redeemed
}

var protectedPage = requireLogin(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("status page"))
})

func browse(handler http.HandlerFunc, method, target string, cookies ...*http.Cookie) *http.Response {
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec.Result()
}

func responseBody(t *testing.T, res *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func responseCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func assertSecureCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	if c.Path != "/" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie %s = %+v, want Path=/, Secure, HttpOnly and SameSite=Lax", c.Name, c)
	}
}

// assertLoginPage checks that res is the login page, not the status page.
func assertLoginPage(t *testing.T, res *http.Response, status int, want ...string) {
	t.Helper()
	if res.StatusCode != status {
		t.Fatalf("status = %d, want %d", res.StatusCode, status)
	}
	// Redirecting to log in again could loop.
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("redirected to %q, want the login page", loc)
	}
	body := responseBody(t, res)
	if strings.Contains(body, "status page") {
		t.Fatal("served the status page")
	}
	assertContains(t, body, append(want, `href="/auth/login"`)...)
}

func TestStatusPageShowsBrowsersWithoutASessionALoginPage(t *testing.T) {
	setupLogin(t)

	res := browse(protectedPage, http.MethodGet, "https://keystore.example.com/")
	assertLoginPage(t, res, http.StatusOK, "Running", "Login with CertKit")
	if len(res.Cookies()) != 0 {
		t.Fatalf("set cookies %v before the login button was clicked", res.Cookies())
	}
}

func TestLoginSendsTheBrowserToCertKit(t *testing.T) {
	setupLogin(t)

	res := browse(handleLogin, http.MethodGet, "https://keystore.example.com/auth/login")
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	login := responseCookie(res, loginCookie)
	if login == nil || login.Value == "" {
		t.Fatal("no login cookie")
	}
	assertSecureCookie(t, login)

	// CertKit gets the verifier's hash, never the verifier.
	want := "https://app.certkit.test/keystore/ks1/login?challenge=" + loginChallenge(login.Value)
	if loc := res.Header.Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestLoginStartsOnTheConfiguredHost(t *testing.T) {
	setupLogin(t)

	res := browse(handleLogin, http.MethodGet, "https://10.0.0.5/auth/login")
	if loc := res.Header.Get("Location"); loc != "https://keystore.example.com/auth/login" {
		t.Fatalf("Location = %q, want the keystore's configured URL", loc)
	}
	if responseCookie(res, loginCookie) != nil {
		t.Fatal("set a login cookie on a host CertKit won't send the browser back to")
	}
}

func TestLoginCallbackLogsIn(t *testing.T) {
	redeemed := setupLogin(t)

	res := browse(handleLoginCallback, http.MethodGet, "https://keystore.example.com/auth/callback?code=code1",
		&http.Cookie{Name: loginCookie, Value: "verifier1"})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("status = %d, Location = %q; want 303 to /", res.StatusCode, res.Header.Get("Location"))
	}
	if len(*redeemed) != 1 || (*redeemed)[0] != "code1 verifier1" {
		t.Fatalf("redeemed %v, want code1 with the login cookie's verifier", *redeemed)
	}
	if c := responseCookie(res, loginCookie); c == nil || c.MaxAge >= 0 {
		t.Fatalf("login cookie = %+v, want it deleted", c)
	}
	session := responseCookie(res, sessionCookie)
	if session == nil || session.Value == "" {
		t.Fatal("no session cookie")
	}
	assertSecureCookie(t, session)
	if session.MaxAge != 24*60*60 {
		t.Fatalf("session cookie Max-Age = %d, want 24 hours", session.MaxAge)
	}

	page := browse(protectedPage, http.MethodGet, "https://keystore.example.com/", session)
	if body := responseBody(t, page); page.StatusCode != http.StatusOK || body != "status page" {
		t.Fatalf("with the session: status = %d, body = %.40q; want the status page", page.StatusCode, body)
	}
}

func TestLoginCallbackNeedsTheLoginCookie(t *testing.T) {
	redeemed := setupLogin(t)

	res := browse(handleLoginCallback, http.MethodGet, "https://keystore.example.com/auth/callback?code=code1")
	assertLoginPage(t, res, http.StatusBadRequest, "Couldn&#39;t log you in", "Try again")
	if len(*redeemed) != 0 {
		t.Fatal("redeemed a code without the browser's verifier")
	}
	if responseCookie(res, sessionCookie) != nil {
		t.Fatal("logged in without the login cookie")
	}
}

func TestLoginCallbackShowsWhyItFailed(t *testing.T) {
	setupLogin(t)
	redeemLogin = func(code, verifier string) (*api.RedeemLoginResponse, error) {
		return nil, errors.New("redeem-login failed: status=401 body=The sign-in code is invalid or has expired.")
	}

	res := browse(handleLoginCallback, http.MethodGet, "https://keystore.example.com/auth/callback?code=code1",
		&http.Cookie{Name: loginCookie, Value: "verifier1"})
	if responseCookie(res, sessionCookie) != nil {
		t.Fatal("logged in although CertKit refused")
	}
	assertLoginPage(t, res, http.StatusBadGateway, "The sign-in code is invalid or has expired.", "Try again")
}

func TestLoginCallbackAfterLoggingInGoesToTheStatusPage(t *testing.T) {
	redeemed := setupLogin(t)
	sessions["s1"] = time.Now().Add(time.Hour)

	res := browse(handleLoginCallback, http.MethodGet, "https://keystore.example.com/auth/callback?code=used",
		&http.Cookie{Name: sessionCookie, Value: "s1"})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("status = %d, Location = %q; want 303 to /", res.StatusCode, res.Header.Get("Location"))
	}
	if len(*redeemed) != 0 {
		t.Fatal("redeemed a code for a browser that's already logged in")
	}
}

func TestExpiredAndUnknownSessionsGetTheLoginPage(t *testing.T) {
	setupLogin(t)
	sessions["old"] = time.Now().Add(-time.Minute)

	for _, id := range []string{"old", "made-up"} {
		res := browse(protectedPage, http.MethodGet, "https://keystore.example.com/", &http.Cookie{Name: sessionCookie, Value: id})
		assertLoginPage(t, res, http.StatusOK, "Login with CertKit")
	}
}

func TestPagesNeedALogin(t *testing.T) {
	setupLogin(t)

	for _, path := range []string{"/", "/logs", "/logs?problems=1", "/logs/download"} {
		res := browse(newMux().ServeHTTP, http.MethodGet, "https://keystore.example.com"+path)
		assertLoginPage(t, res, http.StatusOK, "Login with CertKit")
	}
}

func TestLogoutEndsOnlyTheKeystoreSession(t *testing.T) {
	setupLogin(t)
	sessions["s1"] = time.Now().Add(time.Hour)
	sessions["s2"] = time.Now().Add(time.Hour)
	s1 := &http.Cookie{Name: sessionCookie, Value: "s1"}

	res := browse(handleLogout, http.MethodPost, "https://keystore.example.com/auth/logout", s1)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/?logged-out" {
		t.Fatalf("status = %d, Location = %q; want 303 to /?logged-out", res.StatusCode, res.Header.Get("Location"))
	}
	// The only cookie it touches is its own; CertKit's are left alone.
	if cookies := res.Cookies(); len(cookies) != 1 || cookies[0].Name != sessionCookie || cookies[0].MaxAge >= 0 {
		t.Fatalf("cookies = %v, want just the session cookie deleted", cookies)
	}
	if _, ok := sessions["s1"]; ok {
		t.Fatal("the session is still there")
	}
	if _, ok := sessions["s2"]; !ok {
		t.Fatal("ended another browser's session")
	}

	// A copy of the old cookie no longer works.
	page := browse(protectedPage, http.MethodGet, "https://keystore.example.com/?logged-out", s1)
	assertLoginPage(t, page, http.StatusOK, "You&#39;re logged out", "didn&#39;t log you out of CertKit", "Login with CertKit")
}

func TestStatusPageHasALogoutButton(t *testing.T) {
	setupStatusPage(t)

	rec := httptest.NewRecorder()
	handleRoot(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	res := rec.Result()
	assertContains(t, responseBody(t, res), `<form class="logout" method="post" action="/auth/logout">`)
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("Content-Security-Policy = %q, want it to allow the logout form", csp)
	}
}

func TestLoginChallengeMatchesCertKit(t *testing.T) {
	// CertKit's KeystoreLoginTests checks the same value.
	if got := loginChallenge("abc"); got != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("loginChallenge(abc) = %q", got)
	}
}
