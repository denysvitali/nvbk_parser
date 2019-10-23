package pkg

import (
	"bytes"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
)

var Log logrus.Logger

type NVBKReader struct {
	reader *bytes.Reader
}

func (r *NVBKReader) ReadByteSequence(bs []byte) {
	for i:=0; i<len(bs); i++ {
		r, err := r.reader.ReadByte()
		if err != nil {
			Log.Fatalf("Invalid file, unable to read next byte: %v", err)
			break
		}
		if bs[i] != r {
			Log.Fatalf("Invalid file, expected %c but found %c", bs[i], r)
		}
	}
}

func ReadFile(path string){
	b, err := ioutil.ReadFile(path)

	if err != nil {
		Log.Fatalf("Unable to open file: %v", err)
	}

	nvr := NVBKReader{reader: bytes.NewReader(b)}
	nvr.ReadByteSequence([]byte("OEMNVBK"))
}