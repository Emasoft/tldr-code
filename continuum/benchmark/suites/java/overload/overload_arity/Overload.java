class Overload {
    String handle(int value) {
        return "int";
    }

    String handle(String value) {
        return "string";
    }

    String run() {
        return handle(1);
    }
}
