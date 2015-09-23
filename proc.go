package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

type proc struct {
	Pid    int
	Login  []string
	Shell  bool
	Logger io.Writer

	buf       bytes.Buffer
	lastStdin []byte
}

func (p *proc) LoginData(data []byte) {
	p.Login = append(p.Login, string(data))
}

func (p *proc) Stdin(data []byte) {
	if len(data) == 1 {
		b := data[0]
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
	p.lograw("logout")
}

func (p *proc) LogLogin(login []string) {
	out := fmt.Sprintf("successful login as: %s", strings.Join(login, ", "))
	p.lograw(out)
}

func (p *proc) logline(line []byte) {
	p.lograw(fmt.Sprintf("%#v", string(line)))
}

func (p *proc) lograw(line string) {
	out := fmt.Sprintf("[%d] %s\n", p.Pid, line)
	p.Logger.Write([]byte(out))
}
