function unsafePreview(req) {
  return axios.get(req.query.url);
}

function safePreview(req) {
  return axios.get("https://status.example.test/health");
}

function unsafeCommand(req) {
  return child_process.exec(req.body.command);
}

function safeCommand(req) {
  return child_process.exec("/usr/bin/id");
}
