package main

import (
	"bytes"
	"log"
	"strings"
)

type proc struct {
	Pid    int
	Login  []string
	Shell  bool
	Top    bool
	Logger *log.Logger

	buf       bytes.Buffer
	lastStdin [][]byte
}

func (p *proc) LoginData(data []byte) {
	p.Login = append(p.Login, string(data))
}

func (p *proc) Stdin(data []byte) {
	p.lastStdin = append(p.lastStdin, bytes.Trim(data, "\r\n"))
}

func (p *proc) Stdout(data []byte) {
	if len(p.lastStdin) > 1 {
		for _, v := range p.lastStdin {
			p.buf.Write(v)
		}
	}
	p.lastStdin = nil
	p.buf.Write(data)
	if bytes.Contains(p.buf.Bytes(), []byte("\r\n")) {
		split := bytes.Split(p.buf.Bytes(), []byte("\r\n"))
		for _, v := range split[:len(split)-1] {
			p.logline(v)
		}
		p.buf.Reset()
		p.buf.Write(split[len(split)-1])
	}
}

func (p *proc) Flush() {
	line := p.buf.Bytes()
	if len(line) > 0 {
		p.logline(p.buf.Bytes())
	}
}

func (p *proc) Exit() {
	p.Flush()
	p.Logger.Printf("[%d] <logout>", p.Pid)
}

func (p *proc) LogLogin(login []string, success bool) {
	if success {
		p.Logger.Printf("[%d] <login as: %s>", p.Pid, strings.Join(login, ", "))
	} else {
		p.Logger.Printf("[%d] <login attempt: %s>", p.Pid, strings.Join(login, ", "))
	}
}

func (p *proc) logline(line []byte) {
	p.Logger.Printf("[%d] %#v", p.Pid, string(line))
}
