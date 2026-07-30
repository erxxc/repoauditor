const childProcess = require('child_process')

function runTool(tool, argumentsText) {
  return childProcess.exec(tool + ' ' + argumentsText)
}
