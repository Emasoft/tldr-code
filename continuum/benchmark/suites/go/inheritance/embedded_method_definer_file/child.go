package main

type Child struct {
	Base
}

func (c Child) Run() string {
	return c.Helper()
}
