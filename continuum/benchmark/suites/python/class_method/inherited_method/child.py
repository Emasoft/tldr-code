from base import Base


class Child(Base):
    def run(self):
        return self.helper()
