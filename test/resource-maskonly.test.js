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
  const o = _.cloneDeep(original);
  o._nonce = nonce;
  return tsig.hashJSON(o);
}
const urlToResource = 'https://trusted.com/resources/1';
const t = {
  urlToResource,
  nonce: 'abcdefg',
  mask1: {
    key1: "not masked string",
    key2: { "notmasked": "object" },
    location: {
      'trellis-mask': {
        url: `${urlToResource}/location`,
        nonceurl: `${urlToResource}/_meta/nonce`,
        // hashinfo added after definition
        version: '1.0',
      },
    },
    'keywith/slash': {
      'trellis-mask': {
        'url': `${urlToResource}/keywith/slash`,
      },
    },
  },
  unmasked: {
    _id: '1',
    _meta: { nonce: '12345' },
    key1: "not masked string",
    key2: { "notmasked": "object" },
    location: {
      here: 'we are!!',
    },
    'keywith/slash': {
      'trellis-mask': {
        'url': `${urlToResource}/keywith/slash`,
      },
    },

  }
};
t.mask1.location['trellis-mask'].hashinfo = tmpMakeMeAHash(t.unmasked.location, t.unmasked._meta.nonce);

// Object for storing the resources that are created during testing.
const cur_rescount = 1;
const db = {};

describe('Whole resource functions, only masks (not signatures)', function() {
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

  describe('#maskResource', function() {
    it('should fail if no urlToResource is passed', function() {
      const resource = _.cloneDeep(t.unmasked);
      const paths = [ '/location' ];
      const nonce = t.unmasked._meta.nonce;
      const nonceurl = t.mask1.location['trellis-mask'].nonceurl;
      const result = ml.maskResource({resource, paths, nonce, nonceurl});
      expect(result).to.deep.equal({nonce: false, resource: false, nonceurl: false});
    });

    it('should work for "/location" path with specified nonce and nonceurl', function() {
      const resource = _.cloneDeep(t.unmasked);
      const urlToResource = t.urlToResource;
      const paths = [ '/location' ];
      const nonce = t.unmasked._meta.nonce;
      const nonceurl = t.mask1.location['trellis-mask'].nonceurl;
      const expected = _.cloneDeep(resource);
      expected.location = t.mask1.location; // start with original resource, just mask the one thing
      const result = ml.maskResource({resource,urlToResource,paths,nonce,nonceurl});
      expect(result).to.deep.equal({ nonce, nonceurl, resource: expected });
    });

    it('should work when no nonce is passed', function() {
      const resource = _.cloneDeep(t.unmasked);
      const urlToResource = t.urlToResource;
      const paths = [ '/location' ];
      const nonceurl = t.mask1.location['trellis-mask'].nonceurl;
      const result = ml.maskResource({resource,urlToResource,paths,nonceurl});
      expect(result.nonce).to.have.length.above(0);
    });

    it('should work when no nonceurl is passed', function() {
      const resource = _.cloneDeep(t.unmasked);
      const urlToResource = t.urlToResource;
      const paths = [ '/location' ];
      const nonce = t.unmasked._meta.nonce;
      const result = ml.maskResource({resource,urlToResource,paths,nonce});
      expect(result.nonceurl).to.equal(urlToResource+'/_meta/nonce');
    });
  });

  describe('maskRemoteResourceAsNewResource', function() {
  });

  describe('verifyRemoteResource', function() {
  });

});
