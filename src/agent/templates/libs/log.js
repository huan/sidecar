/*******************************
 * File: templates/libs/log.js
 *******************************/
const log = function () {
  const levelTable = {
    info    : 0,
    verbose : 1,
    silly   : 2,
  }
  let logLevel = levelTable.info

  function verbose (prefix, message, ...args) {
    if (logLevel >= levelTable.verbose) {
      send(logPayload(
        buildMessage('VERB ' + prefix, message, ...args)
      ))
    }
  }

  function silly (prefix, message, ...args) {
    if (logLevel >= levelTable.silly) {
      send(logPayload(
        buildMessage('SILL' + prefix, message, ...args)
      ))
    }
  }

  function setLevel (newLevel) {
    logLevel = newLevel
  }

  return {
    setLevel,
    verbose,
    silly,
  }

  function buildMessage (prefix, message, ...args) {
    return prefix + ' ' + sprintf(message, ...args)
  }

  // Credit: https://stackoverflow.com/a/4795914/1123955
  function sprintf () {
    const args = arguments
    const text = args[0]
    let i = 1
    return text.replace(/%((%)|s|d)/g, function (m) {
      // m is the matched format, e.g. %s, %d
      let val = null
      if (m[2]) {
        val = m[2]
      } else {
        val = args[i]
        // A switch statement so that the formatter can be extended. Default is %s
        switch (m) {
          case '%d':
            val = parseFloat(val)
            if (isNaN(val)) {
              val = 0
            }
            break
        }
        i++
      }
      return val
    })
  }
}()
