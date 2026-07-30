const { execSync } = require('child_process')

function collectCoverage(command) {
  return execSync(command)
}
