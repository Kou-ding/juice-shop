/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { challenges } from '../../data/datacache'
import frisby = require('frisby')
import { expect } from '@jest/globals'
const Joi = frisby.Joi
const utils = require('../../lib/utils')
const security = require('../../lib/insecurity')

const API_URL = 'http://localhost:3000/api'
const REST_URL = 'http://localhost:3000/rest'

const jsonHeader = { 'content-type': 'application/json' }

const getCaptcha = () => {
  return frisby.get(REST_URL + '/captcha')
    .expect('status', 200)
    .expect('header', 'content-type', /application\/json/)
}

const loginUser = (email: string, password: string) => {
  return frisby.post(REST_URL + '/user/login', {
    headers: jsonHeader,
    body: {
      email,
      password
    }
  }).expect('status', 200)
    .then(({ json }) => {
      return { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' }
    })
}

describe('/api/Feedbacks', () => {

  it('GET all feedback', () => {
    return frisby.get(API_URL + '/Feedbacks')
      .expect('status', 200)
  })

  it('POST sanitizes unsafe HTML from comment', async () => {
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        comment: 'I am a harm<script>steal-cookie</script><img src="csrf-attack"/><iframe src="evil-content"></iframe>less comment.',
        rating: 1,
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
      .expect('status', 201)
      .expect('json', 'data', {
        comment: 'I am a harmless comment.'
      })
  })

  if (utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge)) {
    it('POST fails to sanitize masked XSS-attack by not applying sanitization recursively', async () => {
      const { json: captcha } = await getCaptcha()
      return frisby.post(API_URL + '/Feedbacks', {
        headers: jsonHeader,
        body: {
          comment: 'The sanitize-html module up to at least version 1.4.2 has this issue: <<script>Foo</script>iframe src="javascript:alert(`xss`)">',
          rating: 1,
          captchaId: captcha.captchaId,
          captcha: captcha.answer
        }
      })
        .expect('status', 201)
        .expect('json', 'data', {
          comment: 'The sanitize-html module up to at least version 1.4.2 has this issue: <iframe src="javascript:alert(`xss`)">'
        })
    })
  }

  it('POST feedback in another users name as anonymous user', async () => {
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        comment: 'Lousy crap! You use sequelize 1.7.x? Welcome to SQL Injection-land, morons!',
        rating: 1,
        UserId: 3,
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
      .expect('status', 201)
      .expect('json', 'data', { UserId: 3 })
  })

  it('POST feedback in a non-existing users name as anonymous user fails with constraint error', async () => {
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        comment: 'Pickle Rick says your express-jwt 0.1.3 has Eurogium Edule!',
        rating: 0,
        UserId: 4711,
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
      .expect('status', 500)
      .expect('json', 'errors', expect.arrayContaining(['SQLITE_CONSTRAINT: FOREIGN KEY constraint failed']))
  })

  it('POST feedback is associated with current user', async () => {
    const { Authorization } = await loginUser('bjoern.kimminich@gmail.com', 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=')
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: { Authorization, 'content-type': 'application/json' },
      body: {
        comment: 'Stupid JWT secret!',
        rating: 5,
        UserId: 4,
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
      .expect('status', 201)
      .expect('json', 'data', { UserId: 4 })
  })

  it('POST feedback is associated with any passed user ID', async () => {
    const { Authorization } = await loginUser('bjoern.kimminich@gmail.com', 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=')
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: { Authorization, 'content-type': 'application/json' },
      body: {
        comment: 'Bender\'s choice award!',
        rating: 5,
        UserId: 3,
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
      .expect('status', 201)
      .expect('json', 'data', { UserId: 3 })
  })

  it('POST feedback can be created without actually supplying comment', async () => {
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        rating: 1,
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
      .expect('status', 201)
      .expect('json', 'data', { comment: null, rating: 1 })
  })

  it('POST feedback cannot be created without actually supplying rating', async () => {
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
      .expect('status', 400)
      .expect('json', 'message', expect.stringMatching(/notNull Violation: (Feedback\.)?rating cannot be null/))
  })

  it('POST feedback cannot be created with wrong CAPTCHA answer', async () => {
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        rating: 1,
        captchaId: captcha.captchaId,
        captcha: (captcha.answer + 1)
      }
    })
      .expect('status', 401)
  })

  it('POST feedback cannot be created with invalid CAPTCHA id', async () => {
    const { json: captcha } = await getCaptcha()
    return frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        rating: 1,
        captchaId: 999999,
        captcha: 42
      }
    })
      .expect('status', 401)
  })
})

describe('/api/Feedbacks/:id', () => {

  it('GET existing feedback by id is forbidden via public API', () => {
    return frisby.get(API_URL + '/Feedbacks/1')
      .expect('status', 401)
  })

  it('GET existing feedback by id', async () => {
    const { Authorization } = await loginUser('user@example.com', 'password123')
    return frisby.get(API_URL + '/Feedbacks/1', { headers: { Authorization } })
      .expect('status', 200)
  })

  it('PUT update existing feedback is forbidden via public API', () => {
    return frisby.put(API_URL + '/Feedbacks/1', {
      headers: jsonHeader,
      body: {
        comment: 'This sucks like nothing has ever sucked before',
        rating: 1
      }
    })
      .expect('status', 401)
  })

  it('PUT update existing feedback', async () => {
    const { Authorization } = await loginUser('user@example.com', 'password123')
    return frisby.put(API_URL + '/Feedbacks/2', {
      headers: { Authorization },
      body: {
        rating: 0
      }
    })
      .expect('status', 401)
  })

  it('DELETE existing feedback is forbidden via public API', () => {
    return frisby.del(API_URL + '/Feedbacks/1')
      .expect('status', 401)
  })

  it('DELETE existing feedback', async () => {
    const { json: captcha } = await getCaptcha()
    const { json: feedback } = await frisby.post(API_URL + '/Feedbacks', {
      headers: jsonHeader,
      body: {
        comment: 'I will be gone soon!',
        rating: 1,
        captchaId: captcha.captchaId,
        captcha: captcha.answer
      }
    })
    return frisby.del(API_URL + '/Feedbacks/' + feedback.data.id, { headers: jsonHeader })
      .expect('status', 200)
  })
})
