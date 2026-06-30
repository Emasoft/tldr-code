"""FEATURE-1 positive control fixture.

A constructor-typed local receiver MUST resolve per-type:
  - use_cat() calls Cat().speak()  -> Cat.speak  (NOT Dog.speak)
  - use_dog() calls Dog().speak()  -> Dog.speak  (NOT Cat.speak)

Both classes define a method named `speak`, so a pure name-match call graph
would BROADCAST `c.speak()` to both Cat.speak and Dog.speak. The point of this
control is the *correct* per-receiver-type resolution: it must hold at every
stage and must never regress. The parity gate watches it via cluster_goldens.
"""


class Cat:
    def speak(self):
        return "meow"


class Dog:
    def speak(self):
        return "woof"


def use_cat():
    c = Cat()
    return c.speak()


def use_dog():
    d = Dog()
    return d.speak()
