package main

type Service struct{}

func (s Service) helper() string {
	return "ok"
}

func (s Service) Run() string {
	return s.helper()
}
