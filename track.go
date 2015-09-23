package main

import (
	"os"
	"sync"
)

var trackMap = make(map[int]*proc)
var trackLock sync.Mutex

func getProc(pid int) *proc {
	trackLock.Lock()
	defer trackLock.Unlock()
	if p, ok := trackMap[pid]; ok {
		return p
	}
	p := &proc{Pid: pid, Logger: os.Stdout}
	trackMap[pid] = p
	return p
}

func unlinkProc(pid int) {
	trackLock.Lock()
	delete(trackMap, pid)
	trackLock.Unlock()
}
