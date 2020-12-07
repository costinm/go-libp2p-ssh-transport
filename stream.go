package wstransport

import (
	"io"
	"net"
	"time"

	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/protocol"
	"golang.org/x/crypto/ssh"
)

// Terms (SSH to libp2p):
// Channel, represented as net.Conn = MuxedStream

// net.Conn vs MuxedStream
// - LocalAddr, RemoteAddr Addr for net.Conn
// - CloseWrite, CloseRead, Reset for MuxedStream.
// CloseWrite is also implemented in http (closeWriter - not public)

// Implements MuxedStream AND net.Conn
// Also implements ssh.Channel - add SendRequest and Stderr, as well as CloseWrite
type stream struct {
	con *SSHConn
	ch ssh.Channel
	stat network.Stat
}

// net.Conn only
func (c *stream) LocalAddr() net.Addr {
	// MultiAddr doesn't implement 'Network', and the format is not
	// portable.
	return c.con.wsCon.LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.con.wsCon.RemoteAddr()
}

// ssh.Channel
func (c *stream) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return c.ch.SendRequest(name, wantReply, payload)
}

// Stderr returns an io.ReadWriter that writes to this channel
// with the extended data type set to stderr. Stderr may
// safely be read and written from a different goroutine than
// Read and Write respectively.
func (c *stream) Stderr() io.ReadWriter {
	return c.ch.Stderr()
}

// Common
func (c *stream) Read(p []byte) (n int, err error) {
	return c.ch.Read(p)
}

func (c *stream) Write(p []byte) (n int, err error) {
	return c.ch.Write(p)
}

func (c *stream) Close() error {
	return c.ch.Close()
}

// MuxedStream only
func (c *stream) CloseRead() error {
	return c.ch.Close()
}

// MuxedStream only
func (c *stream) Reset() error {
	return c.ch.Close()
}

// MuxedStream and ssh.Channel
func (c *stream) CloseWrite() error {
	return c.ch.CloseWrite()
}

// MuxedStream and net.Conn
func (c *stream) SetDeadline(t time.Time) error {
	return nil
}

func (c *stream) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *stream) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *stream) Stat() network.Stat {
	return c.stat
}

func (c *stream) Conn() network.Conn {
	return c.con
}

func (c *stream) Protocol() protocol.ID {
	return ""
}

func (c *stream) ID() string {
	return ""
}

func (c *stream) SetProtocol(id protocol.ID) {
}


