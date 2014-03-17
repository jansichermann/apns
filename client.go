package apns

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
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
	TcpConnection *net.Conn
	Lock          *sync.Mutex
}

// Constructor. Use this if you want to set cert and key blocks manually.
func BareClient(gateway, certificateBase64, keyBase64 string) (c *Client) {
	c = new(Client)
	c.Gateway = gateway
	c.CertificateBase64 = certificateBase64
	c.KeyBase64 = keyBase64
	return
}

// Constructor. Use this if you want to load cert and key blocks from a file.
func NewClient(gateway, certificateFile, keyFile string) (c *Client) {
	c = new(Client)
	c.Gateway = gateway
	c.CertificateFile = certificateFile
	c.KeyFile = keyFile
	return
}

// Connects to the APN service and sends your push notification.
// Remember that if the submission is successful, Apple won't reply.
func (this *Client) Send(pn *PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)

	payload, err := pn.ToBytes()
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	err = this.ConnectAndWrite(resp, payload)

	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	resp.Success = true
	resp.Error = nil

	return
}

// this is naive
func (this *Client) IsConnected() bool {
	return this.Connection != nil && this.Connection.TcpConnection != nil && this.Connection.TlsConnection != nil
}

func (this *Client) Close() error {
	if this.Connection != nil {

		this.Connection.Lock.Lock()
		defer this.Connection.Lock.Unlock()

		if this.Connection.TlsConnection != nil {
			tcpConn := *this.Connection.TlsConnection
			err := tcpConn.Close()
			if err != nil {
				return err
			}
		}

		if this.Connection.TcpConnection != nil {
			tcpConn := *this.Connection.TcpConnection
			err := tcpConn.Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (this *Client) Connect() (err error) {

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
		Certificates: []tls.Certificate{cert},
	}

	var clientConnection ClientConnection

	conn, err := net.Dial("tcp", this.Gateway)
	if err != nil {
		return err
	}

	clientConnection.TcpConnection = &conn

	tlsConn := tls.Client(conn, conf)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}

	clientConnection.TlsConnection = tlsConn

	this.Connection = &clientConnection

	return nil
}

// In lieu of a timeout (which would be available in Go 1.1)
// we use a timeout channel pattern instead. We start two goroutines,
// one of which just sleeps for TIMEOUT_SECONDS seconds, while the other
// waits for a response from the Apple servers.
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

	// Create one channel that will serve to handle
	// timeouts when the notification succeeds.
	timeoutChannel := make(chan bool, 1)
	go func() {
		time.Sleep(time.Second * TIMEOUT_SECONDS)
		timeoutChannel <- true
	}()

	// This channel will contain the binary response
	// from Apple in the event of a failure.
	responseChannel := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 6, 6)
		this.Connection.TlsConnection.Read(buffer)
		responseChannel <- buffer
	}()

	// First one back wins!
	// The data structure for an APN response is as follows:
	//
	// command    -> 1 byte
	// status     -> 1 byte
	// identifier -> 4 bytes
	//
	// The first byte will always be set to 8.
	resp = NewPushNotificationResponse()
	select {
	case r := <-responseChannel:
		resp.Success = false
		resp.AppleResponse = APPLE_PUSH_RESPONSES[r[1]]
	case <-timeoutChannel:
		resp.Success = true
	}

	return nil
}

func (this *Client) ConnectAndWrite(resp *PushNotificationResponse, payload []byte) (err error) {
	if !this.IsConnected() {
		err = this.Connect()
		if err != nil {
			return err
		}
		defer this.Close()
	}

	err = this.Write(resp, payload)

	return err
}
