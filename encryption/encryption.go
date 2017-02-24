package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const keyPrefix = "behemoth^&%&&*%^&^&%"

//GCMEncrypt ...
//encrypt method
func GCMEncrypt(data []byte, passwrod string) ([]byte, error) {
	key := []byte(keyPrefix + passwrod)
	if len(key[:]) < 32 {
		for i := 0; i < 32-len(key[:]); i++ {
			key = append(key, 1)
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}

//CBCEncrypt ...
//cbc encrypt
func CBCEncrypt(data []byte, passwrod string) ([]byte, error) {
	key := []byte(keyPrefix + passwrod)
	//len of key should be 32
	if len(key[:]) < 32 {
		for i := 0; i < 32-len(key[:]); i++ {
			key = append(key, 1)
		}
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("data size is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}
