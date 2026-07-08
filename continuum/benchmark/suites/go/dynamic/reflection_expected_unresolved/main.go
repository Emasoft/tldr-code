package main

import "reflect"

func Run(w Worker) {
	name := "Start"
	reflect.ValueOf(w).MethodByName(name).Call(nil)
}
