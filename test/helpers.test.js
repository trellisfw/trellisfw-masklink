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
const _ = require('lodash');
const tsig = require('@trellisfw/signatures');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

const ml = require('../index.js'); // mask&link library

function tmpMakeMeAHash(original, nonce) {
  const o = _.cloneDeep(original);
  o._nonce = nonce;
  return tsig.hashJSON(o);
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

describe('helper functions', function() {
  describe('#isMask', function() {
    it('should work with trellis-mask at top level', function() {
      expect(ml.isMask(t.mask1.location)).to.equal(true);
    });
    it('should work with all the stuff a mask is supposed to have', function() {
      expect(ml.isMask(t.mask1.location['trellis-mask'])).to.equal(true);
    });
    it('should fail without url', function() {
      const m = _.cloneDeep(t.mask1.location['trellis-mask']);
      delete m.url;
      expect(ml.isMask(m)).to.equal(false);
    });
    it('should fail without nonceurl', function() {
      const m = _.cloneDeep(t.mask1.location['trellis-mask']);
      delete m.nonceurl;
      expect(ml.isMask(m)).to.equal(false);
    });
    it('should fail without hashinfo {alg,hash}', function() {
      const m = _.cloneDeep(t.mask1.location['trellis-mask']);
      delete m.hashinfo.alg;
      expect(ml.isMask(m)).to.equal(false);
      delete m.hashinfo.hash;
      m.hashinfo.alg = 'SHA256';
      expect(ml.isMask(m)).to.equal(false);
      delete m.hashinfo;
      expect(ml.isMask(m)).to.equal(false);
    });
  });

  describe('#findAllMaskPathsInResource', function() {
    it('should find all the masks, even with a key with a slash in it', async function() {
      const paths = ml.findAllMaskPathsInResource(t.mask1);
      expect(paths).to.deep.equal([ '/location', '/keywith~1slash' ]);
    });

    it('should return an empty array if no masks found', function() {
      const paths = ml.findAllMaskPathsInResource(t.unmasked);
      expect(paths).to.deep.equal([]);
    });
  });

  describe('#domainForMask', function() {
    it('should return the right domain for a valid mask url', function() {
      const domain = ml.domainForMask(t.mask1.location);
      expect(domain).to.deep.equal('https://trusted.com');
    });
    it('should return false for an invalid mask', function() {
      const domain = ml.domainForMask({});
      expect(domain).to.equal(false);
    });
  });

});
