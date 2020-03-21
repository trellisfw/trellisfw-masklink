/* Copyright 2020 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const Promise = require('bluebird');
const expect = chai.expect;
const request = require('superagent');
const nock = require('nock');
const tsig = require('@trellisfw/signatures');
const oada = require('@oada/oada-cache');
const _ = require('lodash');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

const ml = require('../index.js'); // mask&link library

function tmpMakeMeAHash(original, nonce) {
  return tsig.hashJSON({original,nonce});
}
const t = {
  nonce: 'abcdefg',
  mask1: {
    key1: "not masked string",
    key2: { "notmasked": "object" },
    location: {
      'trellis-mask': {
        url: 'https://trusted.com/resources/1/location',
        nonceurl: 'https://trusted.com/resources/1/_meta/nonce',
        // hashinfo added after definition
        version: '1.0',
      },
    },
    'keywith/slash': {
      'trellis-mask': {
        'url': 'https://trusted.com/resources/1/keywith/slash',
      },
    },
  },
  unmasked: {
    _meta: { nonce: '12345' },
    key1: "not masked string",
    key2: { "notmasked": "object" },
    location: {
      here: 'we are!!',
    },

  }
};
t.mask1.location['trellis-mask'].hashinfo = tmpMakeMeAHash(t.unmasked.location, t.unmasked._meta.nonce);

// Object for storing the resources that are created during testing.
const cur_rescount = 1;
const db = {};

describe('Single object (mask) functions', function() {


  describe('#mask', function() {
    it('should produce a valid mask when given valid original, url, nonce, nonceurl', function() {
      const original = t.unmasked.location;
      const url = t.mask1.location['trellis-mask'].url;
      const nonce = t.unmasked._meta.nonce;
      const nonceurl = t.mask1.location['trellis-mask'].nonceurl;
      const expected = { nonce, nonceurl, mask: t.mask1.location };
      const result = ml.mask({original, url, nonce, nonceurl});
      expect(result).to.deep.equal(expected);
    });

    it('should makeup a new nonce when one is not passed', function() {
      const original = t.unmasked.location;
      const url = t.mask1.location['trellis-mask'].url;
      const nonceurl = t.mask1.location['trellis-mask'].nonceurl;
      const expected = { nonceurl, mask: t.mask1.location };
      const result = ml.mask({original, url, nonceurl});
      expect(result.nonce).to.be.a('string');
      expect(result.nonce).to.have.length.above(0);
    });

    it('should not mutate the original object', function() {
      const original = { 'donot': 'changeme' };
      const expected = _.cloneDeep(original);
      const url = t.mask1.location['trellis-mask'].url;
      const nonceurl = t.mask1.location['trellis-mask'].nonceurl;
      const result = ml.mask({original, url, nonceurl});
      expect(original).to.deep.equal(expected);
    });

    it('should throw when no nonceurl is passed', function() {
      const original = t.unmasked.location;
      const url = t.mask1.location['trellis-mask'].url;
      // default URL is "_meta/nonces/location" for a single object
      const expected = t.mask1.location['trellis-mask'].nonceurl + 's/location';
      expect(() => ml.mask({original, url})).to.throw();
    });

    it('should produce a hash different than a hash of just the original (i.e. it used the nonce)', function() {
      const original = t.unmasked.location;
      const url = t.mask1.location['trellis-mask'].url;
      const nonceurl = t.mask1.location['trellis-mask'].nonceurl;
      const unexpected = tsig.hashJSON(original);
      const result = ml.mask({original, url, nonceurl});
      expect(result.mask['trellis-mask'].hashinfo).to.not.deep.equal(unexpected);
    });
  });

  describe('#verify', function() {
    it('should return valid: false, match false for version other than 1.0', function() {
      const mask = _.cloneDeep(t.mask1.location);
      const original = t.unmasked.location;
      const nonce = t.unmasked._meta.nonce;
      mask['trellis-mask'].version = '2.0';
      const {valid, match} = ml.verify({mask,original,nonce});
      expect({valid,match}).to.deep.equal({valid: false, match: false });
    });

    it('should return valid: false, match: false for no hashinfo', function() {
      const mask = _.cloneDeep(t.mask1.location);
      const original = t.unmasked.location;
      const nonce = t.unmasked._meta.nonce;
      mask['trellis-mask'].hashinfo = null;
      const {valid, match} = ml.verify({mask,original,nonce});
      expect({valid,match}).to.deep.equal({valid: false, match: false });
    })

    it('should return valid: true, match: false when nonce is different than original', function() {
      const mask = _.cloneDeep(t.mask1.location);
      const original = t.unmasked.location;
      const nonce = 'nottherealnonce';
      const {valid,match} = ml.verify({mask,original,nonce});
      expect({valid,match}).to.deep.equal({valid: true, match: false });
    });

    it('should return valid: true, match: false when hash is different than original', function() {
      const mask = _.cloneDeep(t.mask1.location);
      const original = t.unmasked.location;
      const nonce = t.unmasked._meta.nonce;
      mask['trellis-mask'].hashinfo = { alg: 'SHA256', hash: 'nottherealhash' };
      const {valid,match} = ml.verify({mask,original,nonce});
      expect({valid,match}).to.deep.equal({valid: true, match: false });
    });

    it('should return valid: true, match: true when everything matches', function() {
      const mask = _.cloneDeep(t.mask1.location);
      const original = t.unmasked.location;
      const nonce = t.unmasked._meta.nonce;
      const {valid,match} = ml.verify({mask,original,nonce});
      expect({valid,match}).to.deep.equal({valid: true, match: true });
    });
  });


  describe('#verifyRemote', function () {
    let connection = false;
    const token = 'thetoken';

    before(async () =>  {
      // Fixed gets:
      nock('https://trusted.com')
        .get('/.well-known/oada-configuration')
        .reply(200, { oada_base_uri: 'https://trusted.com/' })
        .persist()
        
        .get('/resources/1/location')
        .reply(200, t.unmasked.location)
        .persist()

        .get('/resources/1/_meta/nonce')
        .reply(200, JSON.stringify(t.unmasked._meta.nonce))
        .persist()

        .get('/resources/doesnotexist')
        .reply(404, {})
        .persist()

        .get('/resources/badnonce')
        .reply(200, JSON.stringify('nottherealnonce'))
        .persist()

        .get('/resources/badoriginal')
        .reply(200, { 'thisisnot': 'thedroidyouarelookingfor' })
        .persist()

      connection = await oada.connect({ domain: 'https://trusted.com', token, cache: false, websocket: false });
  
    });

    it('should verify when everything matches and we pass a token', async function() {
      const mask = t.mask1.location;
      const { valid, match, original, nonce } = await ml.verifyRemote({mask,token});
      expect({valid,match,original,nonce}).to.deep.equal({
        valid: true,
        match: true,
        original: t.unmasked.location,
        nonce: t.unmasked._meta.nonce,
      });
    });

    it('should verify when everything matches and we pass an oada connection', async function() {
      const mask = t.mask1.location;
      const { valid, match, original, nonce } = await ml.verifyRemote({mask,connection});
      expect({valid,match,original,nonce}).to.deep.equal({
        valid: true,
        match: true,
        original: t.unmasked.location,
        nonce: t.unmasked._meta.nonce,
      });
    });

    it('should fail to verify when mask url 404\'s', async function() {
      const mask = _.cloneDeep(t.mask1.location);
      mask['trellis-mask'].url = "https://trusted.com/resources/doesnotexist";

      const { valid, match, original, nonce } = await ml.verifyRemote({mask,connection});
      expect({valid,match}).to.deep.equal({
        valid: false,
        match: false,
      });
    });

    it('should fail to verify when nonce url 404\'s', async function() {
      const mask = _.cloneDeep(t.mask1.location);
      mask['trellis-mask'].nonceurl = "https://trusted.com/resources/doesnotexist";

      const { valid, match, original, nonce } = await ml.verifyRemote({mask,connection});
      expect({valid,match}).to.deep.equal({
        valid: false,
        match: false,
      });
    });

    it('should fail to verify when mask has no url', async function() {
      const mask = _.cloneDeep(t.mask1.location);
      delete mask['trellis-mask'].url;

      const { valid, match, original, nonce } = await ml.verifyRemote({mask,connection});
      expect({valid,match}).to.deep.equal({
        valid: false,
        match: false,
      });
    });

    it('should return valid: true, match: false when the original returned from the mask url does not match hash', async function() {
      const mask = _.cloneDeep(t.mask1.location);
      mask['trellis-mask'].url = 'https://trusted.com/resources/badoriginal';

      const { valid, match, original, nonce } = await ml.verifyRemote({mask,connection});
      expect({valid,match}).to.deep.equal({
        valid: true,
        match: false,
      });
    });

    it('should return valid: true, match: false when the nonce returned from the nonceurl does not match hash', async function() {
      const mask = _.cloneDeep(t.mask1.location);
      mask['trellis-mask'].nonceurl = 'https://trusted.com/resources/badnonce';

      const { valid, match, original, nonce } = await ml.verifyRemote({mask,connection});
      expect({valid,match}).to.deep.equal({
        valid: true,
        match: false,
      });
    });

  });

});
