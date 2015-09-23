package main

import (
	"./ghostrace/ghost/process"
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
