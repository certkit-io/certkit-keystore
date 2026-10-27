package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
)

// The status page is for the account admins of the CertKit account that owns
// the keystore. Any other browser gets a page saying the keystore is running,
// with a button to log in. Logging in sends the browser to CertKit, which logs
// the user in and sends the browser back to /auth/callback with a code. The
// keystore redeems the code over its signed API, together with the verifier
// from the browser's login cookie. CertKit only ever sees the verifier's
// hash, so a code is useless outside the browser that started the login.

const (
	sessionCookie   = "__Host-certkit-keystore-session"
	loginCookie     = "__Host-certkit-keystore-login"
	sessionLifetime = 24 * time.Hour
	// loginLifetime is how long the browser has to log in to CertKit and
	// come back.
	loginLifetime = 15 * time.Minute
)

// redeemLogin asks CertKit who logged in; tests replace it.
var redeemLogin = api.RedeemLogin

var (
	sessionsMu sync.Mutex
	// sessions maps the session IDs of logged-in browsers to when they
	// expire. They're kept in memory only, so a restart logs everyone out.
	sessions = map[string]time.Time{}
)

//go:embed login_page.html
var loginPageHTML string

var loginPageTemplate = template.Must(template.New("login").Parse(loginPageHTML))

// loginPage is shown instead of the status page to a browser that isn't
// logged in, or whose login failed.
type loginPage struct {
	CertkitURL string
	Heading    string
	Message    string
	// Detail is the error behind a failed login.
	Detail string
	Button string
}

// requireLogin serves next to browsers logged in through CertKit, and a page
// with a login button to any other browser.
func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hasSession(r, time.Now()) {
			next(w, r)
			return
		}

		page := loginPage{
			Heading: "Login for details",
			Message: "Log in with your CertKit account to see this keystore's certificates, private CA keys and health.",
			Button:  "Login with CertKit",
		}
		if r.URL.Query().Has("logged-out") {
			page.Heading = "You're logged out"
			page.Message = "You've logged out of this keystore. That didn't log you out of CertKit."
		}
		renderLoginPage(w, http.StatusOK, page)
	}
}

func hasSession(r *http.Request, now time.Time) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	expires, ok := sessions[cookie.Value]
	return ok && now.Before(expires)
}

// handleLogin starts a login: it keeps a new verifier in the browser's login
// cookie and sends the browser to CertKit with the verifier's challenge.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	setLoginHeaders(w)
	if hasSession(r, time.Now()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	k := config.CurrentConfig.Keystore

	// Cookies belong to a host, and CertKit only sends the browser back to
	// the keystore's configured URL, so the login has to start there.
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if !strings.EqualFold(host, k.Host) {
		http.Redirect(w, r, k.BaseUrl()+"/auth/login", http.StatusFound)
		return
	}

	verifier := rand.Text()
	setCookie(w, loginCookie, verifier, int(loginLifetime.Seconds()))
	http.Redirect(w, r, certkitBaseURL()+"/keystore/"+url.PathEscape(k.Id)+"/login?challenge="+loginChallenge(verifier), http.StatusFound)
}

// handleLoginCallback finishes a login. CertKit sends the browser here with
// a code, which it only redeems with the verifier in this browser's login
// cookie.
func handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	setLoginHeaders(w)
	now := time.Now()

	// Back or reload after logging in.
	if hasSession(r, now) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	login, err := r.Cookie(loginCookie)
	code := r.URL.Query().Get("code")
	if err != nil || login.Value == "" || code == "" {
		renderLoginPage(w, http.StatusBadRequest, loginPage{
			Heading: "Couldn't log you in",
			Message: "The login took too long, or it started in another browser.",
			Button:  "Try again",
		})
		return
	}
	// A verifier is good for one try.
	setCookie(w, loginCookie, "", -1)

	user, err := redeemLogin(code, login.Value)
	if err != nil {
		log.Printf("Status page login failed: %v", err)
		renderLoginPage(w, http.StatusBadGateway, loginPage{
			Heading: "Couldn't log you in",
			Message: "The keystore couldn't confirm the login with CertKit.",
			Detail:  err.Error(),
			Button:  "Try again",
		})
		return
	}

	id := rand.Text()
	sessionsMu.Lock()
	for sid, expires := range sessions {
		if !now.Before(expires) {
			delete(sessions, sid)
		}
	}
	sessions[id] = now.Add(sessionLifetime)
	sessionsMu.Unlock()
	log.Printf("Status page: %s logged in", user.Email)

	setCookie(w, sessionCookie, id, int(sessionLifetime.Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout ends this browser's keystore session, and nothing else: the
// browser stays logged in to CertKit.
func handleLogout(w http.ResponseWriter, r *http.Request) {
	setLoginHeaders(w)
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/?logged-out", http.StatusSeeOther)
}

// loginChallenge is all CertKit sees of a verifier: its SHA-256, base64url
// encoded, as in PKCE.
func loginChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// setCookie sets a cookie for the whole keystore, sent only over HTTPS and
// hidden from scripts. It's SameSite=Lax, not Strict: the browser comes back
// to /auth/callback from CertKit's site, and browsers leave Strict cookies
// off that request and the redirect after it.
func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// setLoginHeaders keeps login responses out of caches, and the code in the
// callback URL out of Referer headers.
func setLoginHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
}

// renderLoginPage shows the login page. Failed logins end up here too rather
// than redirecting: when the browser drops cookies or CertKit can't be
// reached, a redirect would only send the browser around again.
func renderLoginPage(w http.ResponseWriter, status int, page loginPage) {
	page.CertkitURL = certkitBaseURL()
	var buf bytes.Buffer
	if err := loginPageTemplate.Execute(&buf, page); err != nil {
		log.Printf("Failed to render login page: %v", err)
		http.Error(w, "failed to render login page", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; img-src "+certkitOrigin()+
		"; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com"+
		"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}
