// TS caller/callee pair (typed) for the retrieval index test.
function fetchUser(id: string): string {
  return lookup(id);
}

function lookup(id: string): string {
  return id.trim();
}
