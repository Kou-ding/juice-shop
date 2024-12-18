/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import io from 'socket.io-client';

describe('WebSocket', () => {
  let socket;

  beforeEach(done => {
    socket = io('http://localhost:3000', {
      reconnectionDelay: 0,
      forceNew: true
    });
    socket.on('connect', done);
  });

  afterEach(done => {
    if (socket.connected) {
      socket.disconnect();
    }
    done();
  });

  function emitNotifications(messages, done) {
    messages.forEach(message => {
      socket.emit('notification received', message);
    });
    done();
  }

  it('server handles confirmation messages for emitted challenge resolutions', done => {
    const messages = [
      "Find the carefully hidden 'Score Board' page.",
      'Provoke an error that is not very gracefully handled.',
      "Log in with the administrator's user account.",
      'Retrieve a list of all user credentials via SQL Injection',
      "Post some feedback in another user's name.",
      'Wherever you go, there you are.',
      'Place an order that makes you rich.',
      'Access a confidential document.',
      "Access a salesman's forgotten backup file.",
      "Change Bender's password into slurmCl4ssic.",
      'Apply some advanced cryptanalysis to find the real easter egg.'
    ];
    emitNotifications(messages, done);
  });

  it('server handles confirmation message for a non-existent challenge', done => {
    emitNotifications(['Emit a confirmation for a challenge that was never emitted!'], done);
  });

  it('server handles empty confirmation message', done => {
    emitNotifications([undefined], done);
  });
});
