package observer

type Observer interface {
	GetChannel() chan interface{}
}
