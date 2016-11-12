package apns

import (
	"crypto/tls"
	"net"
	"sync"
)

// You'll need to provide your own CertificateFile
// and KeyFile to send notifications. Ideally, you'll
// just set the CertificateFile and KeyFile fields to
// a location on drive where the certs can be loaded,
// but if you prefer you can use the CertificateBase64
// and KeyBase64 fields to store the actual contents.
type Client struct {
	Gateway           string
	CertificateFile   string
	CertificateBase64 string
	KeyFile           string
	KeyBase64         string
	Connection        *ClientConnection
}

type ClientConnection struct {
	TlsConnection *tls.Conn
	Lock          sync.Mutex
}

// Constructor. Use this if you want to load cert and key blocks from a file.
func NewClient(certificateFile, keyFile string) (c *Client) {
	c = new(Client)
	c.CertificateFile = certificateFile
	c.KeyFile = keyFile
	c.Connection = &ClientConnection{}
	return
}

// Connects to the APN service and sends your push notification.
// Remember that if the submission is successful, Apple won't reply.
func (this *Client) Send(conn net.Conn, pn *PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)

	payload, err := pn.ToBytes()
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	err = this.ConnectAndWrite(conn, resp, payload)

	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	resp.Success = true
	resp.Error = nil

	return
}

func (this *Client) Close() error {
	this.Connection.Lock.Lock()
	defer this.Connection.Lock.Unlock()

	if this.Connection.TlsConnection != nil {
		tcpConn := *this.Connection.TlsConnection
		err := tcpConn.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (this *Client) Connect(conn net.Conn) (err error) {
	this.Connection.Lock.Lock()
	defer this.Connection.Lock.Unlock()

	var cert tls.Certificate

	if len(this.CertificateBase64) == 0 && len(this.KeyBase64) == 0 {
		// The user did not specify raw block contents, so check the filesystem.
		cert, err = tls.LoadX509KeyPair(this.CertificateFile, this.KeyFile)
	} else {
		// The user provided the raw block contents, so use that.
		cert, err = tls.X509KeyPair([]byte(this.CertificateBase64), []byte(this.KeyBase64))
	}

	if err != nil {
		return err
	}

	conf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, conf)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}

	this.Connection.TlsConnection = tlsConn

	return nil
}

// In lieu of a timeout (which would be available in Go 1.1)
// we use a timeout channel pattern instead. We start two goroutines,
// one of which just sleeps for TIMEOUT_SECONDS seconds, while the other
// waits for a response from the Apple ts.
//
// Whichever channel puts data on first is the "winner". As such, it's
// possible to get a false positive if Apple takes a long time to respond.
// It's probably not a deal-breaker, but something to be aware of.

func (this *Client) Write(resp *PushNotificationResponse, payload []byte) (err error) {
	this.Connection.Lock.Lock()
	defer this.Connection.Lock.Unlock()

	_, err = this.Connection.TlsConnection.Write(payload)
	if err != nil {
		return err
	}

	return nil
}

func (this *Client) ConnectAndWrite(conn net.Conn, resp *PushNotificationResponse, payload []byte) (err error) {
	err = this.Connect(conn)
	if err != nil {
		return err
	}
	defer this.Close()

	err = this.Write(resp, payload)

	return err
}
