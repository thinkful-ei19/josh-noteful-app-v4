'use strict';

const express = require('express');
const router = express.Router();

const  User = require('../models/user');

router.post('/users', (req, res, next) => {
  const requiredFields = ['username', 'password'];
  const missingField = requiredFields.find(field => !(field in req.body));

  if (missingField) {
    return res.status(422).json({
      code: 422,
      reason: 'ValidationError',
      message: 'Missing Field',
      location: missingField
    });
  }

  const stringFields = ['fullName', 'username', 'password'];
  const nonStringField = stringFields.find( field => field in req.body && typeof req.body[field] !== 'string');

  if (nonStringField){
    return res.status(422).json({
      code: 422,
      reason: 'ValidationError',
      message: 'Incorrect field type: expected string',
      location: nonStringField
    });
  }

  let { username, password, fullName = '' } = req.body;
  fullName = fullName.trim();

  return User.hashPassword(password)
    .then(digest => {
      const newUser = {
        username,
        password: digest,
        fullName
      };
      return User.create(newUser);
    })
    .then(result => {
      return res.status(201).location(`/api/users/${result.id}`).json(result);
    })
    .catch(err => {
      if (err.code === 11000) {
        err = new Error('The username already exists');
        err.status = 400;
      }
      next(err);
    });
});

module.exports = router;