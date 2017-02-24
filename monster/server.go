package monster

/**
server impl simple tcp server and handle all request
**/
import (
	"net"

	p "github.com/elians/behemoth/protocol"
)

type server struct {
	host     string
	password string
	random   bool
}

//Listener ...
//listener interface
type Listener interface {
	Listen() error
}

//NewServer ...
//create new server
func NewServer(host, password string, random bool) Listener {
	return &server{
		host:     host,
		password: password,
		random:   random,
	}
}

func (server *server) Listen() error {
	//current just support tcp server
	listener, err := net.Listen("tcp", server.host)
	if err != nil {
		return err
	}
	//make err chan
	var errChan = make(chan error, 10000)
	defer close(errChan)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go server.handleClient(conn, errChan)
	}
}

func (server *server) handleClient(conn net.Conn, ch chan error) {
	defer conn.Close()
	protocol := p.NewBehemoth(conn, conn)
	err := protocol.ValidateHeader()
	if err != nil {
		ch <- err
		return
	}
	var seq byte
	domain, _ := protocol.GetContent()
	client, err := net.Dial("tcp", domain)
	if err != nil {
		ch <- err
		protocol.FailedReplay(0x05, "cannot connect to remote")
		return
	}
	defer client.Close()
	if !server.random {
		//replay ok and begin to copy data
		err = protocol.Reply()
		ch <- err
	} else {
		err = protocol.ReplyWithDynamicPassword()
		if err != nil {
			ch <- err
			return
		}
		seq, err = protocol.ValidateSubProtocol()
		if err != nil {
			ch <- err
			return
		}
	}
	go func() {
		_, err = dencryptionCopy(conn, client, server.password, int(seq))
		if err != nil {
			ch <- err
			return
		}
	}()
	encryptionCopy(client, conn, server.password, int(seq))
}
