package monster

import (
	"fmt"
	"net"

	p "github.com/elians/behemoth/protocol"
)

type client struct {
	password  string
	dest      string
	vpnserver string
	conn      net.Conn
}

//Sender ...
type Sender interface {
	//request data
	Request() error
}

//NewClient ...
//create client
func NewClient(password, dest, vpnserver string, conn net.Conn) Sender {
	return &client{
		password:  password,
		conn:      conn,
		dest:      dest,
		vpnserver: vpnserver,
	}
}
func (c *client) Request() error {
	defer c.conn.Close()
	conn, err := net.Dial("tcp", c.vpnserver)
	if err != nil {
		fmt.Printf("cannot connect to vpn server %s \n", err)
		return err
	}
	defer conn.Close()
	protocol := p.NewBehemoth(conn, conn)
	err = protocol.SendHandshake(c.dest)
	if err != nil {
		fmt.Printf("error handshake message %s \n", err)
		return err
	}
	code, err := protocol.ValidateReplayHeader()
	if err != nil {
		fmt.Printf("validate header error %s \n", err)
		return err
	}
	if code == 1 {
		//choose method
		err = protocol.SendSubHandShake(0)
		if err != nil {
			fmt.Printf("sub handshake  error %s \n", err)
			return err
		}
		protocol.ValidateSubReplyHeader()
	}

	//copy data
	go func() {
		encryptionCopy(c.conn, conn, c.password, 0)
	}()
	_, err = dencryptionCopy(conn, c.conn, c.password, 0)
	return err
}
