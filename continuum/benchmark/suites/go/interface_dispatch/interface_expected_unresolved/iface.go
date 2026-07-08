package main

type Runner interface {
	Run() string
}

func exec(r Runner) string {
	return r.Run()
}
