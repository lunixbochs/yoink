package main

import (
	"compress/lzw"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type Discard struct{}

func (d *Discard) Write(p []byte) (int, error) {
	return len(p), nil
}

func (d *Discard) Close() error {
	return nil
}

func exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func size(path string) int64 {
	if stat, err := os.Stat(path); err == nil {
		return stat.Size()
	}
	return 0
}

func openLog(path string) (io.WriteCloser, error) {
	if !exists(path) {
		if _, err := os.Create(path); err != nil {
			return nil, err
		}
	}
	var getName = func(i int) string {
		return fmt.Sprintf("%s.%d.gz", path, i)
	}
	// logrotate: find highest number
	next := 1
	for exists(getName(next)) && size(getName(next)) > 0 {
		next++
	}
	// logrotate: move logs
	for i := next - 1; i >= 1; i-- {
		if err := os.Rename(getName(i), getName(i+1)); err != nil {
			return nil, err
		}
	}
	// we're <path>.1.gz
	return os.OpenFile(getName(1), os.O_WRONLY|os.O_CREATE, 0600)
}

func compressStream(file io.WriteCloser) io.WriteCloser {
	return lzw.NewWriter(file, lzw.LSB, 8)
}

func encryptStream(file io.WriteCloser, key string) (io.WriteCloser, error) {
	k, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, len(k))
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	if _, err := file.Write(iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	return &cipher.StreamWriter{S: stream, W: file}, nil
}
