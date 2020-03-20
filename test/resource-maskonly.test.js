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
    _type: 'application/vnd.test.unmasked.1+json',
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


describe('Whole resource functions, only masks (not signatures)', function() {
  let connection = false;
  const token = 'thetoken';

  after(async () => {
    nock.cleanAll()
    nock.enableNetConnect()
  });

  before(async () =>  {
    // Normal operation:
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

      .get('/resources/1')
      .reply(200, t.unmasked)
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

      .put('/resources/newone')
      .reply(function(uri, requestBody) {
        putResource = JSON.parse(requestBody);
        putResourceid = 'resources/newone';
        return [ 200, '' ];
      })
      .persist()

      .put('/resources/1/_meta/nonce')
      .reply(function(uri, requestBody) {
        putNonce = requestBody;
        return [ 200, '' ];
      })
      .persist()

      .post('/resources')
      .reply(function(uri, requestBody) {
        postedResourceid = 'resources/newone';
        postedResource = requestBody;
        return [ 200, '', { 'content-location': `/${postedResourceid}` } ];
      })
      .persist()

    nock('https://trusted.com')
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

    //-----------------------------
    // For maskRemoteResourceAsNewResource, need to be able to return the original but fail post to /resources
    nock('https://cannotpost.com')
      .get('/resources/1')
      .reply(200, t.unmasked)
      .persist()

    nock('https://cannotpost.com')
      .filteringPath(path => { 
        if (path.match(/^\/resources\/[^\/]+/)) {
          return '/doit';
        }
        return false;
      }).put('/doit')
      .reply(404, '')
      .persist()

    //-----------------------------
    // For maskRemoteResourceAsNewResource, need to check what to do when nonce does not exist
    nock('https://nonceresourcetests.com')
      .get('/resources/1')
      .reply(200, t.unmasked)
      .persist()

      .get('/resources/1/_meta/nonce')
      .reply(404,'')
      .persist()

      .put('/resources/1/_meta/nonce')
      .reply(function(uri, requestBody) {
        putNonce = requestBody;
        return [ 200, '' ];
      });


    let noncePutResourceid = false;
    let noncePutResource = false;
    nock('https://nonceresourcetests.com')
      .filteringPath(path => { 
        if (path.match(/^\/resources\/[^\/]+/)) {
          noncePutResourceid = path.slice(1); //path.replace(/^.*resources\/([^\/]+)\/?.*$/, '$1');
          return '/doit';
        }
        return false;
      }).put('/doit')
      .reply(function(uri, requestBody) {
        noncePutResource = JSON.parse(requestBody);
        return [ 200, '', { 'content-location': `/${noncePutResourceid}` } ];
      })
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

  describe('#maskRemoteResourceAsNewResource', function() {
    beforeEach(() => {
      clearPutPost();
    });

    it('should throw when no url is passed', async function() {
      expect(ml.maskRemoteResourceAsNewResource({})).to.eventually.throw();
    });
    it('should throw when an empty paths array is passed', async function() {
      const url = 'https://trusted.com/resources/1';
      expect(ml.maskRemoteResourceAsNewResource({url,paths: []})).to.eventually.throw();
    });

    it('should work when it has all the right stuff', async function()  {
      const url = t.urlToResource;
      const paths = [ '/location' ];
      const newResourceid = await ml.maskRemoteResourceAsNewResource({url, paths, connection});
      expect(newResourceid).to.equal(putResourceid);
      expect(putResource.location).to.deep.equal(t.mask1.location);
    });

    it('should verifyRemote as valid match when it has all the right stuff', async function() {
      const url = t.urlToResource;
      const paths = [ '/location' ];
      const newResourceid = await ml.maskRemoteResourceAsNewResource({url, paths, connection});
      const mask = putResource.location;
      const { valid, match, original, nonce } = await ml.verifyRemote({mask,connection});
      expect({valid,match,original,nonce}).to.deep.equal({
        valid: true,
        match: true,
        original: t.unmasked.location,
        nonce: t.unmasked._meta.nonce
      });      
    });

    it('should throw when the thing at the URL does not exist', async function() {
      const url = 'https://trusted.com/resources/doesnotexist';
      const paths = [ '/location' ];
      expect(ml.maskRemoteResourceAsNewResource({url, paths, connection}))
        .to.eventually.throw();
    });

    it('should throw when it cannot create the new resource', async function() {
      const url = 'https://cannotpost.com/resources/1';
      const paths = [ '/location' ];
      const token = 'cannotusenormalconnection_becausedomainisdifferent'
      let didthrow = false;
      // For some reason, the whole .eventually.throw() did not work here
      try {
        await(ml.maskRemoteResourceAsNewResource({url,paths,token}))
      } catch(e) {
        didthrow = true;
      }
      expect(didthrow).to.equal(true);
    });

    it('should create a new nonce on the resource if there is not one already', async function() {
      const url = 'https://nonceresourcetests.com/resources/1';
      const paths = [ '/location' ];
      const token = 'cannotusenormalconnection_becausedomainisdifferent';
      const newResource = await ml.maskRemoteResourceAsNewResource({url,paths,token});
      expect(putNonce).to.not.equal(t.unmasked._meta.nonce);
      expect(putNonce).to.have.length.above(0);
    });

    it('should re-use the existing nonce on the resource if it is there', async function() {
      const url = t.urlToResource;
      const paths = [ '/location' ];
      const newResourceid = await ml.maskRemoteResourceAsNewResource({url, paths, connection});
      expect(putNonce).to.equal(false); // did not mess with original
      expect(putResource.location).to.deep.equal(t.mask1.location);
    });

    it('should call the signature callback', async function()  {
      const url = t.urlToResource;
      const paths = [ '/location' ];
      let signatureCallback = false;
      const callbackPromise = new Promise((resolve,reject) => {
        signatureCallback = resolve(1);
      });
      const newResourceid = await ml.maskRemoteResourceAsNewResource({url, paths, connection, signatureCallback});
      expect(newResourceid).to.equal(putResourceid);
      expect(putResource.location).to.deep.equal(t.mask1.location);
      expect(callbackPromise).to.eventually.equal(1);
    });

  });

});
