'use strict';

const app = require('../server');
const chai = require('chai');
const chaiHttp = require('chai-http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const { TEST_MONGODB_URI, JWT_SECRET } = require('../config'); ('../config');

const User = require('../models/user');

const expect = chai.expect;
chai.use(chaiHttp);

describe('Noteful API - Login', function () {
  const username = 'testUser';
  const password = 'testPass';
  const fullname = 'Test User';
  const id = '333333333333333333333300';

  before(function () {
    return mongoose.connect(TEST_MONGODB_URI)
      .then(() => mongoose.connection.db.dropDatabase());
  });

  beforeEach(function () {
    return User.hashPassword(password)
      .then(digest => {
        return User.create({
          _id: id,
          username,
          password: digest,
          fullname
        });
      });
    // noop
  });

  afterEach(function () {
    return mongoose.connection.db.dropDatabase();
  });

  after(function () {
    return mongoose.disconnect();
  });

  describe('Noteful /api/login', function () {
    it('Should return a valid auth token', function () {
      return chai.request(app)
        .post('/api/login')
        .send({ username, password })
        .then(res => {
          expect(res).to.have.status(200);
          expect(res.body).to.be.an('object');
          expect(res.body.authToken).to.be.a('string');
      
          const payload = jwt.verify(res.body.authToken, JWT_SECRET);
      
          expect(payload.user).to.not.have.property('password');
          expect(payload.user).to.deep.equal({ id, username, fullname });
        });
    });

    it('Should reject requests with no credentials', function(){
      return chai.request(app)
        .post('/api/login')
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(400);
        });
    });

    it('Should reject requests with incorrect usernames', function() {
      return chai.request(app)
        .post('/api/login')
        .send({username: 'wrongUsername', password})
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });
    });

    it('Should reject requests with incorrect passwords', function() {
      return chai.request(app)
        .post('/api/login')
        .send({username, password: 'wrongPassword'})
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });
    });

  });
});