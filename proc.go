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
	Logger *log.Logger

	buf       bytes.Buffer
	lastStdin []byte
}

func (p *proc) LoginData(data []byte) {
	p.Login = append(p.Login, string(data))
}

func (p *proc) Stdin(data []byte) {
	for _, b := range data {
		if b != '\r' && b != '\n' {
			p.lastStdin = append(p.lastStdin, b)
		}
	}
}

func (p *proc) Stdout(data []byte) {
	if len(p.lastStdin) >= 3 {
		p.buf.Write(p.lastStdin)
		p.lastStdin = nil
	} else {
		max := 0
		// could be improved (sequential scan?)
		// but does its job fairly well as is
		for i, v := range p.lastStdin {
			if bytes.Contains(data, []byte{v}) {
				max = i + 1
			} else {
				break
			}
		}
		p.lastStdin = p.lastStdin[max:]
	}
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
