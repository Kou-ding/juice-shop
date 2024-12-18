/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
import { expect } from '@jest/globals'
import config from 'config'

const API_URL = 'http://localhost:3000/api'
const REST_URL = 'http://localhost:3000/rest'

const jsonHeader = { 'content-type': 'application/json' }
let authHeader: { Authorization: string, 'content-type': string }

const login = (email: string, password: string) => {
  return frisby.post(REST_URL + '/user/login', {
    headers: jsonHeader,
    body: {
      email: email + config.get<string>('application.domain'),
      password: password
    }
  })
    .expect('status', 200)
    .then(({ json }) => {
      authHeader = { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' }
    })
}

const checkDeliveryMethods = (expectedPrice: number) => {
  return frisby.get(API_URL + '/Deliverys', { headers: authHeader })
    .expect('status', 200)
    .expect('header', 'content-type', /application\/json/)
    .then(({ json }) => {
      expect(json.data.length).toBe(3)
      expect(json.data[0].id).toBe(1)
      expect(json.data[0].name).toBe('One Day Delivery')
      expect(json.data[0].price).toBe(expectedPrice)
      expect(json.data[0].eta).toBe(1)
    })
}

const checkDeliveryMethodById = (id: number, expectedPrice: number) => {
  return frisby.get(API_URL + '/Deliverys/' + id, { headers: authHeader })
    .expect('status', 200)
    .expect('header', 'content-type', /application\/json/)
    .then(({ json }) => {
      expect(json.data.id).toBe(id)
      expect(json.data.name).toBe('Fast Delivery')
      expect(json.data.price).toBe(expectedPrice)
      expect(json.data.eta).toBe(3)
    })
}

describe('/api/Deliverys', () => {
  describe('for regular customer', () => {
    beforeAll(() => login('jim', 'ncc-1701'))

    it('GET delivery methods', () => checkDeliveryMethods(0.99))
  })

  describe('for deluxe customer', () => {
    beforeAll(() => login('ciso', 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'))

    it('GET delivery methods', () => checkDeliveryMethods(0.5))
  })
})

describe('/api/Deliverys/:id', () => {
  describe('for regular customer', () => {
    beforeAll(() => login('jim', 'ncc-1701'))

    it('GET delivery method', () => checkDeliveryMethodById(2, 0.5))
  })

  describe('for deluxe customer', () => {
    beforeAll(() => login('ciso', 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'))

    it('GET delivery method', () => checkDeliveryMethodById(2, 0))
  })
})
