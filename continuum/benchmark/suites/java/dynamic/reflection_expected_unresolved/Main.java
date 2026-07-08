class Main {
    static void run() throws Exception {
        Class.forName("Plugin").getMethod("start").invoke(null);
    }
}
