package server

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// lockedBuffer is a log output the test reads while the server writes to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServerErrorLogLeavesOutUntrustedCertificates(t *testing.T) {
	logged := &lockedBuffer{}
	prevOutput, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(logged)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOutput)
		log.SetFlags(prevFlags)
	})

	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = log.New(serverErrorWriter{}, "", 0)
	srv.StartTLS()
	defer srv.Close()

	for alert, want := range map[byte]string{
		46: "",                                   // unknown certificate: browsers
		48: "",                                   // unknown certificate authority: curl
		42: "remote error: tls: bad certificate", // agents
	} {
		before := len(logged.String())

		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		// A fatal alert record in place of a ClientHello. The server logs the
		// failed handshake before it hangs up.
		if _, err := conn.Write([]byte{21, 3, 1, 0, 2, 2, alert}); err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, conn)
		conn.Close()

		got := logged.String()[before:]
		if want == "" {
			if got != "" {
				t.Errorf("alert %d: logged %q, want nothing", alert, got)
			}
		} else if !strings.HasPrefix(got, "http: TLS handshake error from ") || !strings.HasSuffix(got, want+"\n") {
			t.Errorf("alert %d: logged %q, want the handshake error ending in %q", alert, got, want)
		}
	}
}
