package main

type Tree struct{}

func (Tree) GetValue() int {
	return 1
}

type Repo struct {
	trees map[string]Tree
}

func (r Repo) Run() int {
	return r.trees["oak"].GetValue()
}
