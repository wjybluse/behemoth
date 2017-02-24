package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

//GCMDencrypt ...
//dencrypt value
func GCMDencrypt(data []byte, passwrod string) ([]byte, error) {
	key := []byte(keyPrefix + passwrod)
	if len(key) < 32 {
		for i := 0; i <= 32-len(key); i++ {
			key = append(key, 1)
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("error data size")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

//CBCDencrypt ...
//dencrypt
func CBCDencrypt(data []byte, passwrod string) ([]byte, error) {
	key := []byte(keyPrefix + passwrod)
	if len(key) < 32 {
		for i := 0; i < 32-len(key); i++ {
			key = append(key, 1)
		}
	}
	ciphertext := data

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("invalid block size")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}
