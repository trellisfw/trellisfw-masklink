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
  const o = {
    original: _.cloneDeep(original),
    nonce,
  };
  return tsig.hashJSON(o);
}
const urlToResource = 'https://trusted.com/resources/1';
let t = {
  urlToResource,
  nonce: 'abcdefg',
  mask1: {
    _id: '1',
    _type: 'application/vnd.test.unmasked.1+json',
    _meta: { nonce: '12345' },
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
  },
  mask2: {
    key1: {
      'trellis-mask': {
        url: `${urlToResource}/key1`,
        nonceurl: `${urlToResource}/_meta/nonce`,
        // hashinfo added after definition
        version: '1.0',
      },
    },
    key2: { 
      'trellis-mask': {
        url: `${urlToResource}/key2`,
        nonceurl: `${urlToResource}/_meta/nonce`,
        // hashinfo added after definition
        version: '1.0',
      },
    },
    location: {
     'trellis-mask': {
        url: `${urlToResource}/location`,
        nonceurl: `${urlToResource}/_meta/nonce`,
        // hashinfo added after definition
        version: '1.0',
      },
    },
  },
  unmasked: {
    _id: '1',
    _type: 'application/vnd.test.unmasked.1+json',
    _meta: { nonce: '12345' },
    key1: "not masked string",
    key2: { "notmasked": "object" },
    location: {
      here: 'we are!!',
    },
  },
  signed: {}, // to be filled inside before()
  transcriptionSignedUnmasked: {}, // to be filled inside before()
  transcriptionSignedMasked: {},
  transcriptionSignedSingleMultiMask: {},
  transcriptionSignedSuccessiveMultiMask: {},
  transcriptionSignedSuccessiveMultiMaskOutOfOrder: {},
  splitTranscriptionAndMaskSignatures: {},
};
t.mask1.location['trellis-mask'].hashinfo = tmpMakeMeAHash(t.unmasked.location, t.unmasked._meta.nonce);
t.mask2.location['trellis-mask'].hashinfo = tmpMakeMeAHash(t.unmasked.location, t.unmasked._meta.nonce);
t.mask2.key1['trellis-mask'].hashinfo = tmpMakeMeAHash(t.unmasked.key1, t.unmasked._meta.nonce);
t.mask2.key2['trellis-mask'].hashinfo = tmpMakeMeAHash(t.unmasked.key2, t.unmasked._meta.nonce);
t['1'] = t.unmasked;


// Object for storing the resources that are created during testing.
let postedResource = false;
let postedResourceid = false;
let putResourceid = false;
let putResource = false;
let putNonce = false;

function clearPutPost() {
  postedResource = false;
  postedResourceid = false;
  putResourceid = false;
  putResource = false;
  putNonce = false;
}


describe('Whole resource functions, masks AND signatures)', function() {
  let connection = false;
  const token = 'thetoken';
  let keys = false;
  const signer = { name: 'Test Signer', url: 'https://oatscenter.org' };


  after(async () => {
    nock.cleanAll()
    nock.enableNetConnect()
  });

  before(async () =>  {
    keys = await tsig.keys.create(); // { public, private }
    
    // Sign one masked resource:
    t.signed = await tsig.sign(t.mask1, keys.private, { 
      signer, type: 'mask', payload: { 'mask-paths': [ '/location' ] }
    });
    // Make an unmasked thing signed as a transcription
    t.transcriptionSignedUnmasked = await tsig.sign(t.unmasked, keys.private, { 
      signer, type: 'transcription'
    });

    // Make lots of weird permutations of things...
    async function masksign(original, obj_with_mask, replacekeys, opt_payload_paths) {
      const s = _.cloneDeep(original);
      _.each(replacekeys, k => {
        s[k] = obj_with_mask[k];
      });
      const paths = _.map(replacekeys, k => '/'+k); // make paths with leading slashes for jsonpointer
      return await tsig.sign(s, keys.private, { signer, type: 'mask', 
        payload: { 'mask-paths': opt_payload_paths ? opt_payload_paths : paths }
      });
    }

    let s = false;
    // Add mask to that signed thing and sign it again as a mask
    s = await masksign(t.transcriptionSignedUnmasked, t.mask1, [ 'location' ]);
    t.transcriptionSignedMasked = s;

    // Add multiple masks to signed thing and sign it one time as mask with all those paths
    s = await masksign(t.transcriptionSignedUnmasked, t.mask2, [ 'location', 'key1', 'key2' ]);
    t.transcriptionSignedSingleMultiMask = s;

    // Add multiple masks to signed thing, signing after each one
    s = await masksign(t.transcriptionSignedUnmasked, t.mask2, [ 'location' ]);
    s = await masksign(s, t.mask2, [ 'key1' ]);
    s = await masksign(s, t.mask2, [ 'key2' ]);
    t.transcriptionSignedSuccessiveMultiMask = s;

    // Add multiple masks to signed thing, signing after each one, but put the mask-paths in signature out of order
    s = await masksign(t.transcriptionSignedUnmasked, t.mask2, [ 'location' ], ['/key1']);
    s = await masksign(s, t.mask2, [ 'key1' ], ['/key2']);
    s = await masksign(s, t.mask2, [ 'key2' ], ['/location']);
    t.transcriptionSignedSuccessiveMultiMaskOutOfOrder = s;
    
    // Split up the mask signature with a transcription signature in the middle
    s = await masksign(t.unmasked, t.mask2, ['location']);
    s = await tsig.sign(s, keys.private, { signer, type: 'transcription' });
    s = await masksign(s, t.mask2, ['key1']);
    s = await masksign(s, t.mask2, ['key2']);
    t.splitTranscriptionAndMaskSignatures = s;


    // Setup the nock interceptors
    function makeResourceNock(domain,tkey,maskkeys) {

      let scope = nock(domain);
      if (t[tkey] && t[tkey]._meta && t[tkey]._meta.nonce) {
        scope = scope
          .get('/resources/'+tkey+'/_meta/nonce')
          .reply(200, JSON.stringify(t[tkey]._meta.nonce))
          .persist();
      }

      scope = scope
        .get('/resources/'+tkey)
        .reply(200, t[tkey])
        .persist();

      _.each(maskkeys, k => {
        scope = scope
          .get('/resources/'+tkey+'/'+k)
          .reply(function(uri, requestBody) {
            return [ 200, t[tkey][k] ]; // have to use function here so we can try changing masks
          })
          .persist();
      });

      nock(domain)
        .filteringPath(path => { 
          if (path.match(/^\/resources\/[^\/]+/)) {
            putResourceid = path.slice(1); //path.replace(/^.*resources\/([^\/]+)\/?.*$/, '$1');
            return '/doit';
          }
        return false;
      }).put('/doit')
      .reply(function(uri, requestBody) {
        putResource = JSON.parse(requestBody);
        return [ 200, '', { 'content-location': `/${putResourceid}` } ];
      })
      .persist()
    }
    makeResourceNock('https://trusted.com', '1', [ 'location', 'key1', 'key2' ]);
    makeResourceNock('https://trusted.com', 'signed', []);
    makeResourceNock('https://trusted.com', 'transcriptionSignedUnmasked', []);
    makeResourceNock('https://trusted.com', 'transcriptionSignedMasked', []);
    makeResourceNock('https://trusted.com', 'transcriptionSignedSingleMultiMask', []);
    makeResourceNock('https://trusted.com', 'transcriptionSignedSuccessiveMultiMask', []);
    makeResourceNock('https://trusted.com', 'transcriptionSignedSuccessiveMultiMaskOutOfOrder', []);
    makeResourceNock('https://trusted.com', 'splitTranscriptionAndMaskSignatures', []);
     

    connection = await oada.connect({ domain: 'https://trusted.com', token, cache: false, websocket: false });
  
  });

  describe('#signResource', function() {
    it('should work when it has all the right stuff, and signature should verify', async function() {
      const resource = t.mask1;
      const privateJWK = keys.private;
      const paths = [ '/location' ];
      const signed = await ml.signResource({resource,privateJWK,signer,paths});
      const { trusted, valid, unchanged, payload } = await tsig.verify(signed);
      expect(signed.signatures).to.be.an('array');
      expect(signed.signatures).to.have.length(1);
      expect(payload['mask-paths']).to.deep.equal(paths);
      expect(payload['type']).to.equal('mask');
      expect({trusted, valid, unchanged}).to.deep.equal({
        trusted: false,
        valid: true,
        unchanged: true
      });
    });
  });

  describe('#maskAndSignRemoteResourceAsNewResource', function() {

    beforeEach(() => {
      clearPutPost();
    });

    it('should work when it has all the right stuff', async function() {
      const url = t.urlToResource;
      const privateJWK = keys.private;
      const paths = [ '/location' ];
      const newResourceid = await ml.maskAndSignRemoteResourceAsNewResource({url,privateJWK,signer,paths,connection});
      expect(newResourceid).to.equal(putResourceid);
      expect(putResource.signatures).to.be.an('array');
    });

  });


  //------------------------------------------
  // The big one: verifying the remote resource
  describe('#verifyRemoteResource', function() {

    beforeEach(() => {
      clearPutPost();
    });

    it('should work with all the right stuff', async function() {
      const url = 'https://trusted.com/resources/signed';
      const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
      expect({trusted,valid,match,unchanged,original}).to.deep.equal({
        trusted: false,
        valid: true,
        match: true,
        unchanged: true,
        original: t.unmasked,
      });
    });

    it('should return valid=true, match=true, trusted=false, unchanged=false if there is no signature and no masks at all', async function() {
      const url = 'https://trusted.com/resources/1'; // the unmasked resource
      const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
      expect({trusted,valid,match,unchanged}).to.deep.equal({
        valid: true,
        match: true,
        trusted: false,
        unchanged: false,
      });
    });

    it('should work with an initial transcription signature before the mask signature', async function() {
      const url = 'https://trusted.com/resources/transcriptionSignedMasked';
      const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
      expect({trusted,valid,match,unchanged,original}).to.deep.equal({
        valid: true,
        match: true,
        trusted: false,
        unchanged: true,
        original: t.unmasked, // All signatures get removed and validated by verifyRemoteResource
      });
    });

    it('should work with multiple paths in single signature', async function() {
      const url = 'https://trusted.com/resources/transcriptionSignedSingleMultiMask';
      const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
      expect({trusted,valid,match,unchanged,original}).to.deep.equal({
        valid: true,
        match: true,
        trusted: false,
        unchanged: true,
        original: t.unmasked, // All signatures get removed and validated by verifyRemoteResource
      });
    });

    it('should work with successively-applied mask signatures', async function() {
      const url = 'https://trusted.com/resources/transcriptionSignedSuccessiveMultiMask';
      const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
      expect({trusted,valid,match,unchanged,original}).to.deep.equal({
        valid: true,
        match: true,
        trusted: false,
        unchanged: true,
        original: t.unmasked, // All signatures get removed and validated by verifyRemoteResource
      });
    });

    it('should return valid=true, unchanged=false, match=true, trusted=false if paths signed in wrong order', async function() {
      const url = 'https://trusted.com/resources/transcriptionSignedSuccessiveMultiMaskOutOfOrder';
      const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
      expect({trusted,valid,match,unchanged,original}).to.deep.equal({
        valid: true,
        match: true,
        trusted: false,
        unchanged: false, // The only thing that happens here is the signature says that the document looks like it changed since signing
        original: t.unmasked, // All signatures get removed and validated by verifyRemoteResource
      });
    });

    it('should work with masked signatures applied earlier in signature chain', async function () {
      const url = 'https://trusted.com/resources/splitTranscriptionAndMaskSignatures';
      const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
      expect({trusted,valid,match,unchanged,original}).to.deep.equal({
        valid: true,
        match: true,
        trusted: false,
        unchanged: true,
        original: t.unmasked, // All signatures get removed and validated by verifyRemoteResource
      });
     
    });

    it('should show match=false if any of the masks have changed', async function() {
      const original_t = _.cloneDeep(t);
      try {
        const url = 'https://trusted.com/resources/signed';
        t.unmasked.location = 'I CHANGED!!!!!!';
        const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
        expect({trusted,valid,match,unchanged,original}).to.deep.equal({
          valid: true,
          match: false,
          trusted: false,
          unchanged: true,
          original: t.unmasked, // All signatures get removed and validated by verifyRemoteResource
        });
      } finally {
        t = _.cloneDeep(original_t);
      }
    });

    it('should show unchanged=false if the reconstruction does not match top signature', async function() {
      const original_t = _.cloneDeep(t);
      try {
        const url = 'https://trusted.com/resources/transcriptionSignedMasked';
        t.unmasked.location = 'I CHANGED!!!!!!';
        const {trusted,valid,match,unchanged,original} = await ml.verifyRemoteResource({url,connection});
        expect({trusted,valid,match,unchanged,original}).to.deep.equal({
          valid: true,
          match: false,
          trusted: false,
          unchanged: false,
          original: t.unmasked, // All signatures get removed and validated by verifyRemoteResource
        });
      } finally {
        t = _.cloneDeep(original_t);
      }
     
    });

  });

});
