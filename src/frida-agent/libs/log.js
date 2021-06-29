const log = function () {
  let level = 'verbose'

  return {
    verbose: function (prefix, message, ...args) {
      console.log(buildMessage(prefix, message, ...args))
    },
    silly: function(prefix, message, ...args) {
      console.log(buildMessage(prefix, message, ...args))
    },
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
