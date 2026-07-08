package main

type Worker struct{}

func (Worker) Run() string {
	return "worker"
}
