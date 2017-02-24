package protocol

//the protocol content
/**
hand shake
------------------------------
|magic number|ver|len|content|
------------------------------
magic number: 2 bit
ver         : 1 bit,value is 3
len         : 1 bit
content     : variable,value is len

reply
-----------------------------------------------------
|magic number| ver|status|[optional]msg|
-----------------------------------------------------
magic number: request number + random (current year*3+10000)%1992
ver         : version value ,current value is 3
status      : 8 stardand ok
              5 stardand remote error
              1 version error
              2 magic number error
              3 host name or port error
              4 unknown error
              9 change to new encryption method force ,if client doesnot support encryption method,client shutdown
              6 common error

dynamic change encryption method support?


sub protocol support
----------------------
|magic number|ver|seq|
----------------------
magic number: old number +1
ver         : 3
seq         : encryption seq number

reply:
--------------------------
|magic number| ver| status|
--------------------------
status: 9 ok
        5 error
the value of content recommand to encryption
**/

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	version = 0x03 //default version number
	//status code
	statusOk        = 0x08
	statusRemoteErr = 0x05
	statusVerErr    = 0x01
	statusMagic     = 0x02
	statusHostErr   = 0x03
	statusUnknown   = 0x04
	statusChange    = 0x09
	statusCommonErr = 0x06

	//sub status
	stateOk  = 0x09
	stateErr = 0x05
)

var (
	magicNumber = (time.Now().Year()*3 + 10000) % 1992
)

//Behemoth ...
//Behemoth protocol
type behemoth struct {
	reader      io.Reader
	writer      io.Writer
	ver         byte
	magicNumber uint16
	status      byte
	domain      string
	reply       []byte
}

//Protocol ...
//protocol
type Protocol interface {
	//if header is ok,return nil else return error msg
	ValidateHeader() error
	//Get host and port content
	GetContent() (string, error)
	//if sub command support,validate sub command
	ValidateSubProtocol() (byte, error)
	//Reply msg,if wanto change the code
	Reply() error
	//reply with dynamic password
	ReplyWithDynamicPassword() error
	//validate client magic
	ValidateReplyMM(oldNumber uint16) error
	//validate sub MM
	ValidateSubMM(oldNumber, newNumber uint16) error
	//failed reply
	FailedReplay(statuCode byte, msg string) error
	//Send handshake header
	SendHandshake(domain string) error
	//Send sub command handshake
	SendSubHandShake(seq byte) error
	//handle reply header
	ValidateReplayHeader() (byte, error)
	//handle sub reply header
	ValidateSubReplyHeader() error
}

//NewBehemoth ...
//init behemoth protocol
func NewBehemoth(reader io.Reader, writer io.Writer) Protocol {
	return &behemoth{
		reader: reader,
		writer: writer,
		reply:  make([]byte, 0),
	}
}
func (b *behemoth) ValidateReplayHeader() (byte, error) {
	var buf = make([]byte, 1024)
	size, _ := b.reader.Read(buf)
	number := binary.BigEndian.Uint16(buf[:2])
	if number != (b.magicNumber+1024)%1024 {
		return 0, errors.New("invalid magic number")
	}
	if buf[2] != version {
		return 0, errors.New("invalid version")
	}
	if buf[3] != stateOk || buf[3] != statusChange {
		return 0, fmt.Errorf("invalid status %s \n", buf[3:size])
	}
	b.magicNumber = number
	if buf[3] == statusChange {
		return 1, nil
	}
	return 0, nil
}
func (b *behemoth) ValidateSubReplyHeader() error {
	var buf = make([]byte, 4)
	b.reader.Read(buf)
	number := binary.BigEndian.Uint16(buf[:2])
	if number != b.magicNumber+1 {
		return fmt.Errorf("error magic number %d \n", number)
	}
	if buf[2] != version {
		return fmt.Errorf("error version %s \n", buf[2])
	}
	if buf[3] != stateOk {
		return fmt.Errorf("error version %s \n", buf[3])
	}
	return nil
}
func (b *behemoth) SendHandshake(domain string) error {
	b.writer.Write(convert2Byte(uint16(magicNumber)))
	b.writer.Write([]byte{version, uint8(len(domain))})
	_, err := b.writer.Write([]byte(domain))
	b.magicNumber = uint16(magicNumber)
	return err
}
func (b *behemoth) SendSubHandShake(seq byte) error {
	b.writer.Write(convert2Byte(b.magicNumber + 1))
	_, err := b.writer.Write([]byte{version, seq})
	return err
}

func (b *behemoth) ValidateHeader() error {
	var buf = make([]byte, 3)
	size, err := b.reader.Read(buf)
	if err != nil || size < 4 {
		b.reply = append(b.reply, 123, version, statusCommonErr)
		b.writer.Write(b.reply)
		b.writer.Write([]byte("invalid size of buffer"))
		return fmt.Errorf("read error or size is too small err: %s, size %d", err, size)
	}
	//convert to u16
	b.magicNumber = binary.BigEndian.Uint16(buf[:2])
	if b.magicNumber != uint16(magicNumber) {
		b.reply = append(b.reply, 123, version, statusMagic)
		b.writer.Write(b.reply)
		b.writer.Write([]byte("magic number is error"))
		return fmt.Errorf("invalid magic number")
	}
	if buf[2] != version {
		b.reply = append(b.reply, 123, version, statusVerErr)
		b.writer.Write(b.reply)
		b.writer.Write([]byte("version not supported"))
		return fmt.Errorf("invalid version")
	}
	//read ip or domain
	b.status = stateOk
	return nil
}
func (b *behemoth) GetContent() (string, error) {
	var buf = make([]byte, 1)
	b.reader.Read(buf)
	domainLen := buf[0]
	var dbuf = make([]byte, domainLen)
	b.reader.Read(dbuf)
	b.domain = string(dbuf)
	return b.domain, nil
}
func (b *behemoth) ValidateSubProtocol() (byte, error) {
	var buf = make([]byte, 4)
	b.reader.Read(buf)
	newMagicNumber := binary.BigEndian.Uint16(buf[:2])
	err := b.ValidateSubMM(b.magicNumber, newMagicNumber)
	if err != nil {
		b.writer.Write(convert2Byte(newMagicNumber + 1))
		b.writer.Write([]byte{version, stateErr})
		return 0, err
	}
	return buf[3], nil
}
func (b *behemoth) Reply() error {
	b.writer.Write(convert2Byte((b.magicNumber + 1024) % 1024))
	_, err := b.writer.Write([]byte{version, b.status})
	return err
}

func (b *behemoth) ReplyWithDynamicPassword() error {
	//change password
	b.writer.Write(convert2Byte((b.magicNumber + 1024) % 1024))
	_, err := b.writer.Write([]byte{version, statusChange})
	return err
}
func (b *behemoth) ValidateReplyMM(oldNumber uint16) error {
	if (oldNumber+1024)%1024 != b.magicNumber {
		return errors.New("magic number error")
	}
	return nil
}

func (b *behemoth) FailedReplay(statuCode byte, msg string) error {
	b.writer.Write(convert2Byte((b.magicNumber + 1024) % 1024))
	b.writer.Write([]byte{version, statuCode})
	_, err := b.writer.Write([]byte(msg))
	return err
}

func (*behemoth) ValidateSubMM(oldNumber, newNumber uint16) error {
	if oldNumber+1 != newNumber {
		return errors.New("sub magic number error")
	}
	return nil
}

func convert2Byte(number uint16) []byte {
	var buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, number)
	return buf
}
