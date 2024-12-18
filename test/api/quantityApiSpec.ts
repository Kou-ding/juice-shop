/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
import { expect } from '@jest/globals'
import config from 'config'

const REST_URL = 'http://localhost:3000/rest'
const API_URL = 'http://localhost:3000/api'

const jsonHeader = { 'content-type': 'application/json' }

const login = (email: string, password: string) => {
  return frisby.post(`${REST_URL}/user/login`, {
    headers: jsonHeader,
    body: { email, password }
  })
  .expect('status', 200)
  .then(({ json }) => json.authentication.token)
}

const getQuantity = (token: string) => {
  return frisby.get(`${API_URL}/Quantitys`, {
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
  })
  .expect('status', 200)
}

const postQuantity = (token: string, body: object) => {
  return frisby.post(`${API_URL}/Quantitys`, {
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body
  })
  .expect('status', 401)
}

const putQuantity = (token: string, body: object) => {
  return frisby.put(`${API_URL}/Quantitys/1`, {
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body
  })
  .expect('status', 403)
}

const deleteQuantity = (token: string) => {
  return frisby.del(`${API_URL}/Quantitys/1`, {
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
  })
  .expect('status', 401)
}

describe('/api/Quantitys', () => {
  it('GET quantity of all items for customers', () => {
    return login(`jim@${config.get<string>('application.domain')}`, 'ncc-1701')
      .then(token => getQuantity(token))
  })

  it('GET quantity of all items for admin', () => {
    return login(`admin@${config.get<string>('application.domain')}`, 'admin123')
      .then(token => getQuantity(token))
  })

  it('GET quantity of all items for accounting users', () => {
    return login(`accountant@${config.get<string>('application.domain')}`, 'i am an awesome accountant')
      .then(token => getQuantity(token))
  })

  it('POST quantity is forbidden for customers', () => {
    return login(`jim@${config.get<string>('application.domain')}`, 'ncc-1701')
      .then(token => postQuantity(token, { ProductId: 1, quantity: 100 }))
  })

  it('POST quantity forbidden for admin', () => {
    return login(`admin@${config.get<string>('application.domain')}`, 'admin123')
      .then(token => postQuantity(token, { ProductId: 1, quantity: 100 }))
  })

  it('POST quantity is forbidden for accounting users', () => {
    return login(`accountant@${config.get<string>('application.domain')}`, 'i am an awesome accountant')
      .then(token => postQuantity(token, { ProductId: 1, quantity: 100 }))
  })
})

describe('/api/Quantitys/:ids', () => {
  it('GET quantity of all items is forbidden for customers', () => {
    return login(`jim@${config.get<string>('application.domain')}`, 'ncc-1701')
      .then(token => {
        return frisby.get(`${API_URL}/Quantitys/1`, {
          headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
        })
        .expect('status', 403)
        .expect('json', 'error', 'Malicious activity detected')
      })
  })

  it('GET quantity of all items is forbidden for admin', () => {
    return login(`admin@${config.get<string>('application.domain')}`, 'admin123')
      .then(token => {
        return frisby.get(`${API_URL}/Quantitys/1`, {
          headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
        })
        .expect('status', 403)
        .expect('json', 'error', 'Malicious activity detected')
      })
  })

  it('GET quantity of all items for accounting users blocked by IP filter', () => {
    return login(`accountant@${config.get<string>('application.domain')}`, 'i am an awesome accountant')
      .then(token => {
        return frisby.get(`${API_URL}/Quantitys/1`, {
          headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
        })
        .expect('status', 403)
      })
  })

  xit('GET quantity of all items for accounting users from IP 123.456.789', () => { // TODO Check if possible to set IP in frisby tests
    return login(`accountant@${config.get<string>('application.domain')}`, 'i am an awesome accountant')
      .then(token => {
        return frisby.get(`${API_URL}/Quantitys/1`, {
          headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
        })
        .expect('status', 200)
      })
  })

  it('PUT quantity is forbidden for customers', () => {
    return login(`jim@${config.get<string>('application.domain')}`, 'ncc-1701')
      .then(token => putQuantity(token, { quantity: 100 }))
  })

  it('PUT quantity is forbidden for admin', () => {
    return login(`admin@${config.get<string>('application.domain')}`, 'admin123')
      .then(token => putQuantity(token, { quantity: 100 }))
  })

  it('PUT quantity as accounting user blocked by IP filter', () => {
    return login(`accountant@${config.get<string>('application.domain')}`, 'i am an awesome accountant')
      .then(token => putQuantity(token, { quantity: 100 }))
  })

  xit('PUT quantity as accounting user from IP 123.456.789', () => { // TODO Check if possible to set IP in frisby tests
    return login(`accountant@${config.get<string>('application.domain')}`, 'i am an awesome accountant')
      .then(token => putQuantity(token, { quantity: 100 }))
      .then(({ json }) => {
        expect(json.data.quantity).toBe(100)
      })
  })

  it('DELETE quantity is forbidden for accountant', () => {
    return login(`accountant@${config.get<string>('application.domain')}`, 'i am an awesome accountant')
      .then(token => deleteQuantity(token))
  })

  it('DELETE quantity is forbidden for admin', () => {
    return login(`admin@${config.get<string>('application.domain')}`, 'admin123')
      .then(token => deleteQuantity(token))
  })

  it('DELETE quantity is forbidden for users', () => {
    return login(`jim@${config.get<string>('application.domain')}`, 'ncc-1701')
      .then(token => deleteQuantity(token))
  })
})
