/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby');
import { expect } from '@jest/globals';
import config from 'config';
import path from 'path';
import fs from 'fs';

const jsonHeader = { 'content-type': 'application/json' };
const REST_URL = 'http://localhost:3000/rest';

// Reusable function for user login
function loginUser(email: string, password: string) {
  return frisby.post(REST_URL + '/user/login', {
    headers: jsonHeader,
    body: { email, password },
  }).expect('status', 200);
}

// Reusable function for handling CAPTCHA
function handleCaptcha(token: string) {
  return frisby.get(REST_URL + '/image-captcha', {
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
  }).expect('status', 200);
}

// Reusable function for data export
function exportData(token: string, body: any) {
  return frisby.post(REST_URL + '/user/data-export', {
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body,
  }).expect('status', 200);
}

// Reusable function for posting memories
function postMemory(filePath: string, token: string) {
  const file = path.resolve(__dirname, filePath);
  const form = frisby.formData();
  form.append('image', fs.createReadStream(file), 'Valid Image');
  form.append('caption', 'Valid Image');

  return frisby.post(REST_URL + '/memories', {
    headers: {
      Authorization: `Bearer ${token}`,
      // @ts-expect-error FIXME form.getHeaders() is not found
      'Content-Type': form.getHeaders()['content-type'],
    },
    body: form,
  }).expect('status', 200);
}

// Test suite
describe('/rest/user/data-export', () => {
  it('Export data without CAPTCHA', () => {
    return loginUser('bjoern.kimminich@gmail.com', 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=').then(({ json }) => {
      const token = json.authentication.token;
      return exportData(token, { format: '1' }).then(({ json: exportJson }) => {
        const parsedData = JSON.parse(exportJson.userData);
        expect(parsedData.username).toBe('bkimminich');
        expect(parsedData.email).toBe('bjoern.kimminich@gmail.com');
      });
    });
  });

  it('Export data with invalid CAPTCHA answer', () => {
    return loginUser('bjoern.kimminich@gmail.com', 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=').then(({ json }) => {
      const token = json.authentication.token;
      return handleCaptcha(token).then(() => {
        return exportData(token, { answer: 'AAAAAA', format: 1 }).expect('status', 401).expect('bodyContains', 'Wrong answer to CAPTCHA. Please try again.');
      });
    });
  });

  it('Export data with valid CAPTCHA answer', () => {
    return loginUser('bjoern.kimminich@gmail.com', 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=').then(({ json }) => {
      const token = json.authentication.token;
      return handleCaptcha(token).then(({ json: captchaAnswer }) => {
        return exportData(token, { answer: captchaAnswer.answer, format: 1 }).then(({ json: exportJson }) => {
          const parsedData = JSON.parse(exportJson.userData);
          expect(parsedData.username).toBe('bkimminich');
          expect(parsedData.email).toBe('bjoern.kimminich@gmail.com');
        });
      });
    });
  });

  it('Export data including memories', () => {
    return loginUser('jim@' + config.get<string>('application.domain'), 'ncc-1701').then(({ json }) => {
      const token = json.authentication.token;
      return postMemory('../files/validProfileImage.jpg', token).then(() => {
        return exportData(token, { format: '1' }).then(({ json: exportJson }) => {
          const parsedData = JSON.parse(exportJson.userData);
          expect(parsedData.memories[0].caption).toBe('Valid Image');
          expect(parsedData.memories[0].imageUrl).toContain('assets/public/images/uploads/valid-image');
        });
      });
    });
  });

  it('Export data including orders', () => {
    return loginUser('amy@' + config.get<string>('application.domain'), 'K1f.....................').then(({ json }) => {
      const token = json.authentication.token;
      return frisby.post(REST_URL + '/basket/4/checkout', {
        headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      }).expect('status', 200).then(() => {
        return exportData(token, { format: '1' }).then(({ json: exportJson }) => {
          const parsedData = JSON.parse(exportJson.userData);
          expect(parsedData.orders[0].products[0].name).toBe('Raspberry Juice (1000ml)');
        });
      });
    });
  });
});
