const { execFileSync } = require('child_process')

function collectCoverage(binary, files) {
  return execFileSync(binary, files, { shell: false })
}
