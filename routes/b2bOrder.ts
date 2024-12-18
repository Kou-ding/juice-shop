/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { NodeVM } from 'vm2' // Replacing 'notevil' with 'vm2'
import { type Request, type Response, type NextFunction } from 'express'
import challengeUtils = require('../lib/challengeUtils')

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
const security = require('../lib/insecurity')

module.exports = function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        // Create a NodeVM instance from vm2, providing the sandbox environment
        const vm = new NodeVM({
          console: 'off',          // Disable console.log and other console methods
          sandbox: { orderLinesData }, // Provide a controlled environment
          require: {
            external: false,       // Disable access to external modules
            builtin: ['path'],     // Allow only specific built-in modules if necessary
          },
          timeout: 2000            // Timeout to prevent infinite loops
        })
        
        // Run the orderLinesData code in the sandbox environment
        vm.run(`safeEval(${JSON.stringify(orderLinesData)})`)  // Ensure orderLinesData is a safe string
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
