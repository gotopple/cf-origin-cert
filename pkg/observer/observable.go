package observer

import (
	"sync"
)

type Observable struct {
	observers []chan interface{}
	mu        *sync.Mutex
}

func MakeObservable() *Observable {
	return &Observable{
		observers: make([]chan interface{}, 0),
		mu:        &sync.Mutex{},
	}
}

func (o *Observable) Attach(observer Observer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observers = append(o.observers, observer.GetChannel())
}

func (o *Observable) Detach(observer Observer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, v := range o.observers {
		c := observer.GetChannel()
		if v == c {
			o.observers = append(o.observers[:i], o.observers[i+1:]...)
			return
		}
	}
}

func (o *Observable) Notify(evt interface{}) {
	for _, v := range o.observers {
		v <- evt
	}
}
