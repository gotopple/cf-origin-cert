package agent

import (
	"fmt"
	"github.com/gotopple/cf-origin-cert/internal"
	"github.com/ionrock/procs"
	"log"
)

type PostHookObserver struct {
	ch              chan interface{}
	postHookCommand string
}

func NewPostHookObserver(command string) *PostHookObserver {
	result := &PostHookObserver{
		make(chan interface{}, 2),
		command,
	}

	go func() {
		for {
			evt := <-result.ch
			if internal.IsInstanceOf(evt, (*CertKeyPair)(nil)) {
				result.onNewCertificate()
			}
		}
	}()

	return result
}

func (a *PostHookObserver) GetChannel() chan interface{} {
	return a.ch
}

func (a *PostHookObserver) onNewCertificate() {
	p := procs.NewProcess(a.postHookCommand)
	p.ErrHandler = func(line string) string {
		fmt.Printf("[POST HOOK - STD ERR] %s\n", line)
		return line
	}
	p.OutputHandler = func(line string) string {
		fmt.Printf("[POST HOOK - STD OUT] %s\n", line)
		return line
	}
	err := p.Run()

	if err != nil {
		log.Fatal("Post hook failed", err)
	}
	fmt.Println("Executed post hook")
}
