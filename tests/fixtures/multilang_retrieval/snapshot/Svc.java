// Java caller/callee pair for the retrieval index test.
class Svc {
    String handle(String id) {
        return runQuery(id);
    }

    String runQuery(String id) {
        return db.execute("SELECT * FROM users WHERE id = " + id);
    }
}
