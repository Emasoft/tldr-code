package main

type Widget struct{}

func NewWidget() *Widget {
	w := &Widget{}
	w.init()
	return w
}

func (w *Widget) init() {}
