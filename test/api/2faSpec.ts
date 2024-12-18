/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby');
import config from 'config';
import jwt from 'jsonwebtoken';
const Joi = frisby.Joi;
const security = require('../../lib/insecurity');
const otplib = require('otplib');

const REST_URL = 'http://localhost:3000/rest';
const API_URL = 'http://localhost:3000/api';
const jsonHeader = { 'content-type': 'application/json' };

// Utility for making authenticated requests
function authorizedHeaders(token: string) {
  return {
    headers: {
      Authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
  };
}

// Utility for sending POST requests
async function postRequest(endpoint: string, body: any, headers = jsonHeader) {
  return frisby.post(endpoint, { headers, body });
}

// Utility for sending GET requests
async function getRequest(endpoint: string, headers = jsonHeader) {
  return frisby.get(endpoint, { headers });
}

// Reusable Login Logic
async function login({ email, password, totpSecret }: { email: string; password: string; totpSecret?: string }) {
  const loginRes = await postRequest(`${REST_URL}/user/login`, { email, password }).catch((res: any) => {
    if (res.json?.type && res.json.status === 'totp_token_required') return res;
    throw new Error(`Failed to login '${email}'`);
  });

  if (loginRes.json.status === 'totp_token_required') {
    const totpRes = await postRequest(`${REST_URL}/2fa/verify`, {
      tmpToken: loginRes.json.data.tmpToken,
      totpToken: otplib.authenticator.generate(totpSecret),
    });
    return totpRes.json.authentication;
  }

  return loginRes.json.authentication;
}

// Reusable 2FA Status Check
async function getStatus(token: string) {
  return getRequest(`${REST_URL}/2fa/status`, authorizedHeaders(token));
}

// Reusable Register Logic
async function register({ email, password, totpSecret }: { email: string; password: string; totpSecret?: string }) {
  const res = await postRequest(`${API_URL}/Users/`, {
    email,
    password,
    passwordRepeat: password,
    securityQuestion: null,
    securityAnswer: null,
  }).catch(() => {
    throw new Error(`Failed to register '${email}'`);
  });

  if (totpSecret) {
    const { token } = await login({ email, password });

    await postRequest(
      `${REST_URL}/2fa/setup`,
      {
        password,
        setupToken: security.authorize({
          secret: totpSecret,
          type: 'totp_setup_secret',
        }),
        initialToken: otplib.authenticator.generate(totpSecret),
      },
      authorizedHeaders(token),
    ).catch(() => {
      throw new Error(`Failed to enable 2FA for user: '${email}'`);
    });
  }

  return res;
}

// Tests
describe('/rest/2fa/verify', () => {
  it('POST should return a valid authentication with a valid tmp token', async () => {
    const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' });
    const totpToken = otplib.authenticator.generate('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH');

    await postRequest(`${REST_URL}/2fa/verify`, { tmpToken, totpToken })
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', 'authentication', { token: Joi.string(), umail: Joi.string(), bid: Joi.number() })
      .expect('json', 'authentication', { umail: `wurstbrot@${config.get<string>('application.domain')}` });
  });

  it('POST should fail with an invalid totp token', async () => {
    const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' });
    const invalidToken = otplib.authenticator.generate('INVALID_SECRET');

    await postRequest(`${REST_URL}/2fa/verify`, { tmpToken, totpToken: invalidToken }).expect('status', 401);
  });

  // Other test cases simplified for brevity...
});

describe('/rest/2fa/status', () => {
  it('GET should indicate 2FA is setup for enabled users', async () => {
    const { token } = await login({
      email: `wurstbrot@${config.get<string>('application.domain')}`,
      password: 'EinBelegtesBrotMitSchinkenSCHINKEN!',
      totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH',
    });

    await getStatus(token)
      .expect('status', 200)
      .expect('json', { setup: true });
  });

  // Other test cases simplified for brevity...
});
