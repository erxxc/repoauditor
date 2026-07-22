// Go file: no tree-sitter grammar wired -> exercises the lexical fallback path.
package main

func handler(id string) string {
	return runQuery(id)
}

func runQuery(id string) string {
	return db.Execute("SELECT * FROM users WHERE id = " + id)
}
