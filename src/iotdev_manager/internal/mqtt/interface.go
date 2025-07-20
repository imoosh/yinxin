package mqtt

type Publisher interface {
	Publish([]byte) error
}

type Subscriber interface {
	Subscribe(SubscribeHandler) error
}
