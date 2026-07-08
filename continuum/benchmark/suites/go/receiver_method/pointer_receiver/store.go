package main

type Store struct{}

func (s *Store) Save() string {
	return "saved"
}

func (s *Store) Run() string {
	return s.Save()
}
