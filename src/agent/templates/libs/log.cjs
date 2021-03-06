/*******************************
 * File: templates/libs/log.cjs
 *******************************/
const log = (() => {
  const levelTable = {
    silent  : 0,
    error   : 1,
    warn    : 2,
    info    : 3,
    verbose : 4,
    silly   : 5,
  }
  let logLevel = levelTable.info

  function error (prefix, message, ...args) {
    if (logLevel >= levelTable.error) {
      send(__sidecar__payloadLog(
        'error',
        prefix,
        sprintf(message, ...args)
      ))
    }
  }

  function warn (prefix, message, ...args) {
    if (logLevel >= levelTable.warn) {
      send(__sidecar__payloadLog(
        'warn',
        prefix,
        sprintf(message, ...args)
      ))
    }
  }

  function info (prefix, message, ...args) {
    if (logLevel >= levelTable.info) {
      send(__sidecar__payloadLog(
        'info',
        prefix,
        sprintf(message, ...args)
      ))
    }
  }

  function verbose (prefix, message, ...args) {
    if (logLevel >= levelTable.verbose) {
      send(__sidecar__payloadLog(
        'verbose',
        prefix,
        sprintf(message, ...args)
      ))
    }
  }

  function silly (prefix, message, ...args) {
    if (logLevel >= levelTable.silly) {
      send(__sidecar__payloadLog(
        'silly',
        prefix,
        sprintf(message, ...args)
      ))
    }
  }

  function level (newLevel) {
    if (typeof newLevel === 'number') {
      logLevel = newLevel
    } else if (newLevel in levelTable) {
      logLevel = levelTable[newLevel]
    } else {
      console.error('unknown newLevel, enable maximum logging')
      logLevel = 99
    }
  }

  return {
    level,
    error,
    warn,
    info,
    verbose,
    silly,
  }

  // function buildMessage (prefix, message, ...args) {
  //   return prefix + ' ' + sprintf(message, ...args)
  // }

  // Credit: https://stackoverflow.com/a/4795914/1123955
  function sprintf () {
    const args = arguments
    const text = args[0]
    let i = 1
    return text.replace(/%((%)|s|d|o)/g, function (m) {
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
          case '%o':
            val = JSON.stringify(val)
            break
        }
        i++
      }
      return val
    })
  }
})()

/**
 * For unit testing under Node.js
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ...module.exports,
    log,
  }
}
