package main

import (
	"compress/lzw"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func decompressStream(file io.Reader) io.Reader {
	if file == nil {
		return nil
	}
	return lzw.NewReader(file, lzw.LSB, 8)
}

func decryptStream(file io.Reader, key string) (io.Reader, error) {
	if file == nil {
		return nil, nil
	}
	k, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, len(k))
	if _, err := file.Read(iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	return &cipher.StreamReader{S: stream, R: file}, nil
}

func openLogs(logPath, credPath, key string, lzw bool) (logFile, credFile io.Reader, err error) {
	if logPath != "" {
		logFile, err = os.Open(logPath)
		if err != nil {
			return
		}
	}
	if credPath != "" {
		credFile, err = os.Open(credPath)
		if err != nil {
			return
		}
	}
	if key != "" {
		logFile, err = decryptStream(logFile, key)
		if err != nil && err != io.EOF {
			return
		}
		credFile, err = decryptStream(credFile, key)
		if err != nil {
			return
		}
	}
	if lzw {
		logFile = decompressStream(logFile)
		credFile = decompressStream(credFile)
	}
	if logFile == nil && credFile == nil {
		return nil, nil, errors.New("specify either a log or cred file")
	}
	return
}

func dumpLogs(logs, creds io.Reader) {
	if creds != nil {
		io.Copy(os.Stdout, creds)
	}
	if logs != nil {
		io.Copy(os.Stdout, logs)
	}
}

func tailLogs(logs, creds io.Reader) {
	fmt.Println("not implemented")
}
