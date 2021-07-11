/*****************************************
 * File: "templates/agent.mustache"
 * --------------------------------
 * Sidecar Frida Agent Mustache Template
 *
 *  https://github.com/huan/sidecar
 *  Huan <zixia@zixia.net>
 *  June 24, 2021
 *****************************************/

/***********************************
 * File: "templates/agent.mustache"
 *  > Partials: "libs/payload.js"
 ***********************************/
/********************************************
 * File: templates/lib/payload.js
 *
 * To make sure the payload typing is right
 * See: sidecar-body/payload-schema.ts
 ********************************************/
/**
 * SidecarPayloadHook
 */
const sidecarPayloadHook = (
  method, // string
  args,   // Arguments, Array
) => ({
  payload: {
    args,
    method,
  },
  type: 'hook',
})

/**
 * SidecarPayloadLog
 */
const sidecarPayloadLog = (
  level,    // verbose, silly
  prefix,   // module name
  message,  // string
) => ({
  payload: {
    level,
    message,
    prefix,
  },
  type : 'log',
})

/**
 * For unit testing under Node.js
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ...module.exports,
    sidecarPayloadHook,
    sidecarPayloadLog,
  }
}

/***********************************
 * File: "templates/agent.mustache"
 *  > Partials: "libs/log.js"
 ***********************************/
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
      send(sidecarPayloadLog(
        'verbose',
        prefix,
        sprintf(message, ...args)
      ))
    }
  }

  function silly (prefix, message, ...args) {
    if (logLevel >= levelTable.silly) {
      send(sidecarPayloadLog(
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

/**
 * For unit testing under Node.js
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ...module.exports,
    log,
  }
}

log.level('info')

/****************************************************
 * File: "templates/agent.mustache"
 *  > Get base address for target "/home/huan/git/sidecar/examples/chatbox/chatbox-linux"
 ****************************************************/
const sidecarModuleBaseAddress = Module.getBaseAddress('chatbox-linux')

/***********************************
 * File: "templates/agent.mustache"
 *  > Variable: "initAgentScript"
 ***********************************/
/**
 * Call -> moHelper(message)
 *  MO Sidecar Agent Helper
 */
const moNativeFunction = new NativeFunction(
  sidecarModuleBaseAddress.add(0x11e9),
  'int',
  ['pointer'],
)

function moHelper (message) {
  const buf = Memory.allocUtf8String(message)
  return moNativeFunction(buf)
}

/**
 * Hook -> mtNativeCallback
 *  MT Sidecar Agent Helper
 */
const mtNativeCallback = new NativeCallback(() => {}, 'void', ['pointer'])
const mtNativeFunction = new NativeFunction(mtNativeCallback, 'void', ['pointer'])

Interceptor.attach(
  sidecarModuleBaseAddress.add(0x121f),
  {
    onEnter: args => {
      log.verbose('AgentScript',
        'Interceptor.attach() onEnter() arg0: %s',
        args[0].readUtf8String(),
      )
      /**
       * Huan(202107):
       *  1. We MUST use `setImmediate()` for calling `mtNativeFunction(arg0),
       *    or the hook to mtNativeCallback will not be triggered. (???)
       *  2. `args` MUST be saved to arg0 so that it can be access in the `setImmediate`
       */
      const arg0 = args[0]
      setImmediate(() => mtNativeFunction(arg0))
    }
  }
)


/********************************************
 * File: "templates/agent.mustache"
 *  > Partials: "native-functions.mustache"
 ********************************************/
/************************************************************
 * File: "native-functions.mustache"
 * ---------------------------------
 * Native Function List: automaticated generated by Sidecar
 *
 *  Author: Huan <zixia@zixia.net>
 *  https://github.com/huan/sidecar
 ************************************************************/


    /*****************************************************************
     * File: "native-function-agent.mustache"
     *
     * Native Function: mo
     *  - varName: moHelper
     *  - Parameters: 'pointer'
     *  - Ret: int
     ******************************************************************/
    function mo_NativeFunction_wrapper (...args) {
      log.verbose(
        'SidecarAgent',
        'mo(%s)',
        args.join(', '),
      )

      /**
        * Huan(202107):
        *  `target` at here is a `agent` type `target`,
        *  which means that it is a javascript function name
        *  defined from the `initAgentScript`
        */
      const ret = moHelper(...[ args[0] ])

      /**
       * Return what js function returned.
       *  no conversion
       */
      return ret
    }



/**************************************
 * File: "templates/agent.mustache"
 *  > Partials: "interceptors.mustache"
 **************************************/
/*********************************************************
 * File: "templates/interceptors.mustache"
 *
 * Interceptors List: automaticated generated by Sidecar
 *  template file: "interceptors.mustache"
 *
 *  Author: Huan <zixia@zixia.net>
 *  https://github.com/huan/sidecar
 *********************************************************/


    /**********************************************************
     * File: "interceptors-agent.mustache"
     *
     * Interceptor Target: mt
     *  - varName: mtNativeCallback
     *  - Parameters: 'pointer'
     **********************************************************/
    Interceptor.attach(
      /**
       *  Huan(202107): `target` at here is a native ptr
       *    which is declared in the `initAgentScript`
       *    for workaround
       */
      mtNativeCallback,
      {
        onEnter: args => {
          log.verbose(
            'SidecarAgent',
            'Interceptor.attach(%s) onEnter()',
            'mtNativeCallback',
          )

          send(sidecarPayloadHook(
            'mt',
            [ args[0].readUtf8String() ]
          ), null)

        },
      }
    )



/********************
 * RPC Exports Init *
 ********************/
function init () {
  log.verbose('SidecarAgent', 'init()')

  /**
   * Huan(202106) return 42 to let caller to make sure that
   *  this function has been runned successfully.
   */
  return 42
}

rpc.exports = {
  init,
  ...rpc.exports,
}

/**************************************
 * File: "templates/agent.mustache"
 *  > Partials: "rpc-exports.mustache"
 **************************************/
/*********************************************************
 * File: "rpc-exports.mustache"
 * ----------------------------
 * RPC Exports List: automaticated generated by Sidecar
 *
 *  Author: Huan <zixia@zixia.net>
 *  https://github.com/huan/sidecar
 *********************************************************/
rpc.exports = {
  ...rpc.exports,
  mo: mo_NativeFunction_wrapper,
}

