package monster

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	r := strings.NewReader("llllllllllllllllllllllllllllllllllllllllllllllll")
	var buffer = make([]byte, 1024)
	var temp = bytes.NewBuffer(buffer)
	size, err := encryptionCopy(r, temp, "hahahhdehhhh", 0)
	if err != nil {
		fmt.Printf("err is %s\n", err)
		t.Fail()
	} else {
		fmt.Println(size)
		output := fmt.Sprint(temp)
		temp = bytes.NewBuffer(buffer)
		_, err := dencryptionCopy(strings.NewReader(output), temp, "hahahhdehhhh", 0)
		if err != nil {
			fmt.Printf("decode error %s \n", err)
			t.Fail()
		} else {
			r := fmt.Sprint(temp)
			fmt.Printf("result is %s \n", r)
		}
	}
}
