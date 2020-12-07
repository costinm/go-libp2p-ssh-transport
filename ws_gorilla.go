package wstransport

import (
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"context"
	"net/http"

	"github.com/libp2p/go-libp2p-core/peer"
	manet "github.com/multiformats/go-multiaddr/net"

	ws "github.com/gorilla/websocket"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
)

// WS is used for compatibility with 'legacy' infrastructure.
// HTTP/2 POST is another option - it may work in cases where WS doesn't.
// If 'legacy' is not a problem - use H2 POST or QUIC
//
//

// Adapter for Gorilla Websocket.
// Alternatives:
// - x/net/websocket - seems to be deprecated
// - nhooyr.io/websocket - may be better, but not urgent to change.


// GracefulCloseTimeout is the time to wait trying to gracefully close a
// connection before simply cutting it.
var GracefulCloseTimeout = 100 * time.Millisecond

var _ net.Conn = (*Conn)(nil)

// Conn implements net.Conn interface for gorilla/websocket.
type Conn struct {
	*ws.Conn
	DefaultMessageType int
	reader             io.Reader
	closeOnce          sync.Once

	readLock, writeLock sync.Mutex
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()

	if c.reader == nil {
		if err := c.prepNextReader(); err != nil {
			return 0, err
		}
	}

	for {
		n, err := c.reader.Read(b)
		switch err {
		case io.EOF:
			c.reader = nil

			if n > 0 {
				return n, nil
			}

			if err := c.prepNextReader(); err != nil {
				return 0, err
			}

			// explicitly looping
		default:
			return n, err
		}
	}
}

func (c *Conn) prepNextReader() error {
	t, r, err := c.Conn.NextReader()
	if err != nil {
		if wserr, ok := err.(*ws.CloseError); ok {
			if wserr.Code == 1000 || wserr.Code == 1005 {
				return io.EOF
			}
		}
		return err
	}

	if t == ws.CloseMessage {
		return io.EOF
	}

	c.reader = r
	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	if err := c.Conn.WriteMessage(c.DefaultMessageType, b); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close closes the connection. Only the first call to Close will receive the
// close error, subsequent and concurrent calls will return nil.
// This method is thread-safe.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err1 := c.Conn.WriteControl(
			ws.CloseMessage,
			ws.FormatCloseMessage(ws.CloseNormalClosure, "closed"),
			time.Now().Add(GracefulCloseTimeout),
		)
		err2 := c.Conn.Close()
		switch {
		case err1 != nil:
			err = err1
		case err2 != nil:
			err = err2
		}
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr {
	return NewAddr(c.Conn.LocalAddr().String())
}

func (c *Conn) RemoteAddr() net.Addr {
	return NewAddr(c.Conn.RemoteAddr().String())
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}

	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	// Don't lock when setting the read deadline. That would prevent us from
	// interrupting an in-progress read.
	return c.Conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	// Unlike the read deadline, we need to lock when setting the write
	// deadline.

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	return c.Conn.SetWriteDeadline(t)
}

// NewConn creates a Conn given a regular gorilla/websocket Conn.
func NewConn(raw *ws.Conn) *Conn {
	return &Conn{
		Conn:               raw,
		DefaultMessageType: ws.BinaryMessage,
	}
}

// Default gorilla upgrader
var upgrader = ws.Upgrader{
	// Allow requests from *all* origins.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	Subprotocols: []string{PROTO_SSH},
}

const PROTO_SSH = "/ssh/1.0"

func (t *SSHTransport) maDial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	wsurl, err := parseMultiaddr(raddr)
	if err != nil {
		return nil, err
	}

	wscl := &ws.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 5 * time.Second,
		Subprotocols: []string{
			PROTO_SSH,
		},
	}

	wscon, _, err := wscl.Dial(wsurl, nil)
	if err != nil {
		return nil, err
	}

	mnc, err := manet.WrapNetConn(NewConn(wscon))
	if err != nil {
		wscon.Close()
		return nil, err
	}

	if PROTO_SSH == wscon.Subprotocol() {

	}

	return t.NewCapableConn(mnc, false)
}

func (t *SSHTransport) maListen(a ma.Multiaddr) (transport.Listener, error) {
	lnet, lnaddr, err := manet.DialArgs(a)
	if err != nil {
		return nil, err
	}

	nl, err := net.Listen(lnet, lnaddr)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse("http://" + nl.Addr().String())
	if err != nil {
		nl.Close()
		return nil, err
	}

	malist, err := t.wrapListener(nl, u)
	if err != nil {
		nl.Close()
		return nil, err
	}
	if t.Mux != nil {
		t.Mux.Handle(t.Prefix, malist)
	} else {
		go malist.serve()
	}
	return malist, nil
}

func (t *SSHTransport) wrapListener(l net.Listener, origin *url.URL) (*listener, error) {
	laddr, err := manet.FromNetAddr(l.Addr())
	if err != nil {
		return nil, err
	}
	wsma, err := ma.NewMultiaddr("/ws")
	if err != nil {
		return nil, err
	}
	laddr = laddr.Encapsulate(wsma)

	return &listener{
		t: t,
		laddr:    laddr,
		l: l,
		incoming: make(chan *Conn),
		closed:   make(chan struct{}),
	}, nil
}
