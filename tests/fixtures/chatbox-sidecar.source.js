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
 * SidecarBodyEventPayloadHook
 */
const hookPayload = (
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
 * SidecarBodyEventPayloadLog
 */
const logPayload = (
  level,
  prefix,
  message,
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
    hookPayload,
    logPayload,
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
      send(logPayload(
        'verbose',
        prefix,
        sprintf(message, ...args)
      ))
    }
  }

  function silly (prefix, message, ...args) {
    if (logLevel >= levelTable.silly) {
      send(logPayload(
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
 *  > Variable: "initAgentSource"
 ***********************************/
const agentMo = new NativeFunction(
  sidecarModuleBaseAddress.add(0x11e9),
  'int',
  ['pointer'],
)

const agentMt_PatchCode = Memory.alloc(Process.pageSize)

// Memory.patchCode(agentMt_PatchCode, Process.pageSize, function (code) {
//   var cw = new X86Writer(code, { pc: agentMt_PatchCode })
//   cw.putNop()
//   cw.putNop()
//   cw.putNop()
//   cw.putNop()
//   cw.putRet()
//   cw.flush()
// })

// const agentMt_NativeCallback = new NativeCallback(
//   (...args) => {
//     log.verbose('FridaAgent', 'agentMt() faint from Frida: %s', args[0].readUtf8String())
//     send(hookPayload(
//       'mt',
//       {
//         ...[args[0].readUtf8String()],
//         // Huan(202107): TODO: add name alias support
//       }
//     ), null)
//   },
//   'void',
//   ['pointer'],
// )

// const agentMt_NativeFunction = new NativeFunction(
//   // agentMt_NativeCallback,
//   agentMt_PatchCode,
//   'void',
//   ['pointer'],
// )

Interceptor.attach(
  sidecarModuleBaseAddress.add(0x121f),
  {
    onEnter: args => {
      console.log('interceptor called', args[0].readUtf8String())
      send(hookPayload({
        type: 'hook',
        payload: {
          method: 'mt',
          args: {
            content: args[0].readUtf8String(),
          },
        },
      }))
    } // agentMt_NativeFunction(args[0]),
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
     *  - varName: agentMo
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
        *  defined from the `initAgentSource`
        */
      const ret = agentMo(...[ args[0] ])

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
     *  - varName: agentMt_PatchCode
     *  - Parameters: 'pointer'
     **********************************************************/
    Interceptor.attach(
      /**
       *  Huan(202107): `target` at here is a native ptr
       *    which is declared in the `initAgentSource`
       *    for workaround
       */
      agentMt_PatchCode,
      {
        onEnter: args => {
          log.verbose(
            'SidecarAgent',
            'Interceptor.attach(%s) onEnter()',
            'agentMt_PatchCode',
          )

          send(hookPayload(
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
