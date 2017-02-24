package monster

import (
	"encoding/binary"
	"io"

	"github.com/elians/behemoth/encryption"
)

//encrypt function
type encrypter func(data []byte, passwrod string) ([]byte, error)

//dencrypt function
type dencrypter func(data []byte, passwrod string) ([]byte, error)

func encryptionCopy(reader io.Reader, writer io.Writer, password string, seq int) (int, error) {
	var buf = make([]byte, 8*1024)
	var size = 0
	var err error
	for {
		nr, er := reader.Read(buf)
		if nr > 0 {
			enBuf, err := getEncrypters()[seq](buf[:nr], password)
			if err != nil {
				return 0, err
			}
			ws := len(enBuf)
			writer.Write(convert2Byte(uint16(ws)))
			nw, ew := writer.Write(enBuf)
			if nw > 0 {
				size += nw
			}
			if nw < ws {
				writer.Write(enBuf[nw:ws])
			}
			if ew != nil {
				return 0, err
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return size, err
}

func dencryptionCopy(reader io.Reader, writer io.Writer, password string, seq int) (int, error) {
	var buf = make([]byte, 2)
	var size = 0
	var err error
	for {
		reader.Read(buf)
		len := binary.BigEndian.Uint16(buf)
		var bffer1 = make([]byte, len)
		nr, er := reader.Read(bffer1)
		if nr > 0 {
			enBuf, err := getDencrypters()[seq](bffer1[:nr], password)
			if err != nil {
				return 0, err
			}
			nw, ew := writer.Write(enBuf)
			if nw > 0 {
				size += nw
			}
			if ew != nil {
				return 0, err
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return size, err
}
func getEncrypters() []dencrypter {
	return []dencrypter{
		encryption.CBCEncrypt,
		encryption.GCMEncrypt,
	}
}

func getDencrypters() []encrypter {
	return []encrypter{
		encryption.CBCDencrypt,
		encryption.GCMDencrypt,
	}
}

func convert2Byte(number uint16) []byte {
	var buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, number)
	return buf
}
