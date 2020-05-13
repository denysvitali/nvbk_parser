package pkg

import (
	"bytes"
	"encoding/binary"
	"github.com/Sirupsen/logrus"
	"github.com/denysvitali/nvbk_parser/pkg/nvbk"
	"io/ioutil"
	"log"
)

var Log logrus.Logger

type NVBKReader struct {
	reader   *bytes.Reader
	position int
}

func (r *NVBKReader) ReadByteSequence(bs []byte) {
	for i := 0; i < len(bs); i++ {
		readByte, err := r.reader.ReadByte()
		if err != nil {
			Log.Fatalf("Invalid file, unable to read next byte: %v", err)
			break
		}
		r.position++
		if bs[i] != readByte {
			Log.Fatalf("Invalid file, expected %c but found %c", bs[i], readByte)
		}
	}
}

func (r *NVBKReader) Skip(length int) {
	for i := 0; i < length; i++ {
		_, err := r.reader.ReadByte()
		if err != nil {
			log.Fatal(err)
		}
		r.position++
	}
}

func (r *NVBKReader) ReadBytes(length int) ([]byte, error) {
	var buffer = make([]byte, 0)
	for i := 0; i < length; i++ {
		b, err := r.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		r.position++
		buffer = append(buffer, b)
	}
	return buffer, nil
}

func (r *NVBKReader) AssumePosition(pos int) {
	if pos != r.position {
		logrus.Fatalf("assume position failed: expected %#x but was %#x", pos, r.position)
	}
}

func (r *NVBKReader) PeekByte() byte {
	b, err := r.reader.ReadByte()
	if err != nil {
		logrus.Fatalf("unable to peek byte")
	}
	err = r.reader.UnreadByte()
	if err != nil {
		logrus.Fatalf("unable to unread byte")
	}
	return b
}

func ReadFile(path string) nvbk.NVBKFile {
	b, err := ioutil.ReadFile(path)

	if err != nil {
		Log.Fatalf("Unable to open file: %v", err)
	}

	nvr := NVBKReader{reader: bytes.NewReader(b)}
	nvr.ReadByteSequence([]byte("OEMNVBK"))
	nvr.Skip(5) // Unkn_1
	nvr.AssumePosition(0xc)

	if  nvr.PeekByte() == 0x00 {
		log.Fatalf("invalid byte found!")
	}

	//var1 := 0
	//var2 := 0


	// Ignore everything past this line:
	total_items_bytes, err := nvr.ReadBytes(2)
	total_items := binary.BigEndian.Uint16(total_items_bytes)

	outputFile := nvbk.NVBKFile{
		Header: nvbk.NVBKHeader{},
	}

	outputFile.Header.Total = int(total_items)

	logrus.Debugf("found %d entries", total_items)
	return outputFile
}
