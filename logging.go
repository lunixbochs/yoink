package main

import (
	"bufio"
	"compress/lzw"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"net"
	"os"
	"os/signal"
	"regexp"
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

func readPass(fd int) ([]byte, error) {
	// make sure an interrupt won't break the terminal
	sigint := make(chan os.Signal)
	state, err := terminal.GetState(fd)
	if err != nil {
		return nil, err
	}
	go func() {
		for _ = range sigint {
			terminal.Restore(fd, state)
			fmt.Println("^C")
			os.Exit(1)
		}
	}()
	signal.Notify(sigint, os.Interrupt)
	defer func() {
		signal.Stop(sigint)
		close(sigint)
	}()
	return terminal.ReadPassword(fd)
}

func sshKeyboardAuth(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	answers = make([]string, len(questions))
	fmt.Printf(instruction)
	var ans string
	for i, q := range questions {
		fmt.Printf(q)
		if echos[i] {
			var bans []byte
			bans, err = readPass(0)
			ans = string(bans)
		} else {
			reader := bufio.NewReader(os.Stdin)
			ans, err = reader.ReadString('\n')
		}
		if err != nil {
			return nil, err
		}
		answers = append(answers, ans)
	}
	return answers, nil
}

// user(:pass)?@host+port:file
var scpPathRe = regexp.MustCompile(`^([^:@]+)(:[^@]+)?@([^:]+)(\+[0-9]+)?:(.*)$`)

func openLog(path string) (io.WriteCloser, error) {
	m := scpPathRe.FindStringSubmatch(path)
	if m == nil {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	} else {
		user, pass, host, port, path := m[1], m[2], m[3], m[4], m[5]
		if path == "" {
			return nil, errors.New("blank remote file path")
		}
		if port == "" {
			port = "22"
		} else {
			port = port[1:]
		}
		config := ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(sshKeyboardAuth)},
		}
		if pass != "" {
			config.Auth = append(config.Auth, ssh.Password(pass[1:]))
		} else {
			config.Auth = append(config.Auth, ssh.PasswordCallback(func() (string, error) {
				fmt.Printf("Password: ")
				pass, err := readPass(0)
				fmt.Println()
				return string(pass), err
			}))
		}
		client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), &config)
		if err != nil {
			return nil, err
		}
		session, err := client.NewSession()
		if err != nil {
			return nil, err
		}
		inputStream, err := session.StdinPipe()
		if err != nil {
			session.Close()
			return nil, err
		}
		cmd := fmt.Sprintf("cat > %s", shellEscape(path))
		if err := session.Start(cmd); err != nil {
			session.Close()
			return nil, err
		}
		return inputStream, nil
	}
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
