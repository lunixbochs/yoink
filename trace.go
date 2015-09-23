package main

import (
	"encoding/binary"
	"log"
	"strings"

	"./ghostrace/ghost"
	"./ghostrace/ghost/sys/call"
)

func trace(sshd int, logger *log.Logger, credLog *log.Logger) error {
	tracer := ghost.NewTracer()
	trace, err := tracer.Trace(sshd)
	if err != nil {
		return err
	}
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
					parproc := getProc(parent.Pid(), logger)
					var login = parproc.Login
					parproc.Login = nil

					par2 := parent.Parent()
					if login == nil && par2 != nil {
						p2proc := getProc(par2.Pid(), logger)
						login = p2proc.Login
						p2proc.Login = nil
					}
					proc := getProc(parent.Pid(), logger)
					proc.Shell = true
					credLog.Printf("%#v\n", strings.Join(login, ", "))
					proc.LogLogin(login, true)
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
		proc := getProc(pid, logger)
		if event.Exit {
			if proc.Shell {
				proc.Exit()
			} else if proc.Login != nil {
				proc.LogLogin(proc.Login, false)
			}
			unlinkProc(pid)
			continue
		}
		var sc interface{} = event.Syscall
		if !proc.Shell {
			// preauth, look for login IO
			parent := event.Process.Parent()
			if parent != nil {
				pproc := getProc(parent.Pid(), logger)
				if sc, ok := sc.(*call.Write); ok {
					if sc.Fd == 4 && len(sc.Data) >= 6 && isPrintable(sc.Data[4:]) {
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
				if sc.Fd >= 8 {
					proc.Stdout(sc.Data)
				}
			case *call.Write:
				if sc.Fd >= 7 {
					proc.Stdin(sc.Data)
				}
			}
		}
	}
	return nil
}
