package main

import (
	"encoding/binary"
	"log"

	"./ghostrace/ghost"
	"./ghostrace/ghost/sys/call"
)

func trace(sshd int, logger *log.Logger) error {
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
					var login []string
					par2 := parent.Parent()
					if par2 != nil {
						p2proc := getProc(par2.Pid(), logger)
						login = p2proc.Login
					}
					proc := getProc(parent.Pid(), logger)
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
		proc := getProc(pid, logger)
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
				pproc := getProc(parent.Pid(), logger)
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
