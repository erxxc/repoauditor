// JS caller/callee pair for the retrieval index test.
function runQuery(userId) {
  const conn = db.connect("app.db");
  return conn.execute("SELECT * FROM users WHERE id = " + userId);
}

function handler(userId) {
  return runQuery(userId);
}

const helper = (x) => runQuery(x);
