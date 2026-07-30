const { execSync, spawn } = require('child_process')

function readVersion() {
  execSync('node --version')
  return spawn('node', ['--version'], { shell: false })
}
