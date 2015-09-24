package main

import (
	"github.com/lunixbochs/ghostrace/ghost/process"
	"strings"
)

var sshdPaths = []string{
	"/usr/bin/sshd",
	"/usr/sbin/sshd",
}

var shellPaths = []string{
	"/bin/bash",
	"/bin/csh",
	"/bin/ksh",
	"/bin/sh",
	"/bin/tcsh",
}

func strMatch(paths []string, path string) bool {
	for _, s := range paths {
		if s == path {
			return true
		}
	}
	return false
}

func procMatch(p process.Process, paths []string) bool {
	if p == nil {
		return false
	}
	if strMatch(paths, p.Exe()) {
		return true
	}
	cmdline := p.Cmdline()
	if cmdline != nil && strMatch(paths, cmdline[0]) {
		return true
	}
	return false
}

func isSshd(p process.Process) bool {
	return procMatch(p, sshdPaths)
}

func isPrintable(p []byte) bool {
	for _, c := range p {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func shellEscape(s string) string {
	s = strings.Replace(s, `'`, `'"'"'`, -1)
	return `'` + s + `'`
}
