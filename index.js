const _ = require('lodash');
const urllib = require('url');
const Promise = require('bluebird');
const jsonpointer = require('json-pointer');
const oada = require('@oada/oada-cache');
const tsig = require('@trellisfw/signatures');

const debug = require('debug');
const trace = debug('trellisfw-masklink:trace');
const  info = debug('trellisfw-masklink:info');
const  warn = debug('trellisfw-masklink:warn');
const error = debug('trellisfw-masklink:error');

//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
// Helpers:
//---------------------------------------------------------------------------
//---------------------------------------------------------------------------

async function connectionOrToken({connection,token,domain}) {
  if (!connection) {
    if (!token) throw new Error('trellisfw-masklink#connectionOrToken: You must pass either a token or an oada-cache connection');
    trace(`#connectionOrToken: No connection passed, creating one with token using inferred domain ${domain}`);
    connection = await oada.connect({ domain, token, cache: false, websocket: false });
  }
  return connection;
}
function makeNonce() {
  return tsig.jose.util.base64url.encode(tsig.jose.util.randomBytes(32));
}
function isMask(t) {
  if (!t) return false;
  if (typeof t !== 'object') return false; // a string or number cannot be a mask
  if (t['trellis-mask']) t = t['trellis-mask'];
  if (!t.hashinfo) return false;
  return (typeof t.url === 'string'
    && typeof t.nonceurl === 'string'
    && typeof t.hashinfo.alg === 'string'
    && typeof t.hashinfo.hash === 'string');
}
function domainFromURL(url) {
  const u = urllib.parse(url);
  let p = '';
  if (u.port) p = ':'+u.port;
  return u.protocol + '//' + u.host + p; // https://some.domain:port 
  // that's where the /.well-known should live
}
function pathFromURL(url) {
  const u = urllib.parse(url);
  return u.pathname; // /a/b/c
}
// This one is exported because it is handy for creating connections to a domain
function domainForMask(mask) {
  if (mask && mask['trellis-mask']) mask = mask['trellis-mask'];
  if (!mask || !mask.url) {
    warn('#domainForMask: warning: mask is null or has no valid url');
    return false;
  }
  return domainFromURL(mask.url);
}
// This is exported as well:
function findAllMaskPathsInResource(resource) {
  function recursiveFindMaskPaths(curobj, curpath) {
    // No more paths to be found down this branch
    if (!curobj) return [];
    if (typeof curobj !== 'object') return [];
    // Do we terminate search at this path?
    if (curobj['trellis-mask']) return [ curpath ];
    // Get paths for each key child and merge into one long list
    return _.reduce(_.keys(curobj), (acc,key) => {
      // concat paths from peers with all paths under this key
      const newpath = jsonpointer.compile(jsonpointer.parse(curpath).concat(key));
      return acc.concat(recursiveFindMaskPaths(curobj[key], newpath));
    }, []);
  }
  return recursiveFindMaskPaths(resource, '');
}



//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
// Functions for dealing with mask objects by themselves (i.e. not entire resources)
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------
// Creates a nonce, adds that to the original object as original._nonce, then hashes that.
// Returns the nonce and the trellis-mask object.  Note that you have to save the nonce
// somewhere or you can't verify the hash.
// This returns an object with a `nonce` key and a `mask` key.  
// The `mask` key looks like `{ trellis-mask: { ... } }`: i.e. it's the exact thing you replace the original with.
// nonce: if you pass a nonce, it will use that.  If you don't, it will generate a random one.
// nonceurl: whether you pass a nonce or not, you must specify where you intend to store the nonce for later retrieval.
//           IMPORTANT: this function does not store the nonce, that's up to you to do.  This just puts that nonceurl
//           in the resulting mask.
// NOTE: the url cannot terminate at a resource: i.e https://some.domain/resources/12345.  You can't mask an entire resource.
function mask({original, url, nonce, nonceurl}) {
  if (!nonce) { 
    nonce = makeNonce(); // 256 bits of randomness in a base64 string
    trace(`#mask: created nonce ${nonce}`);
  }
  trace('using nonce: ', nonce);
  if (!nonceurl) {
    error('#mask: No nonceurl passed');
    throw new Error('no nonceurl was passed: you have to say where to store the nonce that I make.  You could do /resources/<resourceid>/_meta/nonce for a single nonce per resource');
    // There is no guarantee that someone always uses the /resources path (as opposed to /bookmarks), so 
    // we can't simply default to _meta/nonces/... like we wanted to without making this function async
    // and fetching the thing to get the resources url in the content-location
    //nonceurl = url.replace(/(resources\/[^\/]+)(.*)$/, '$1/_meta/nonces$2');
  }
  // Since the original can be a string or a number in addition to an array or object,
  // we construct an "outer" JSON object to hold it and put the nonce there
  const tm = {
    version: '1.0',
    hashinfo: tsig.hashJSON({original,nonce}),
    url,
    nonceurl,
  };
  trace(`#mask: returning mask = { "trellis-mask": ${JSON.stringify(tm,false,'  ')} }`);
  return { nonce, nonceurl, mask: { 'trellis-mask': tm } };
}


// valid: true|false => whether the mask, original, and nonce have valid forms.  Says nothing about whether they match
// match: true|false => if valid, tells whether the original actually matches the mask
// details: array of strings to help you debug what happened internally
// mask: the masked object
// original: the original thing that was masked
// nonce: the nonce used in the hash originally when the mask was created
function verify({mask, original, nonce}) {
  // Allow someone to send either the object containing trellis-mask, or the trellis-mask itself.
  if (mask && mask['trellis-mask']) {
    mask = mask['trellis-mask'];
  }
  if (!mask) {
    trace(`#verify: Mask is null`);
    return { valid: false, match: false, details: [ `Mask is null` ] };
  }
  if (mask.version !== '1.0') {
    trace(`#verify: version (${mask.version}) is unknown`);
    return { valid: false, match: false, details: [ `version (${mask.version}) is unknown`] };
  }
  if (!mask.hashinfo) {
    trace(`#verify: mask has no hashinfo`);
    return { valid: false, match: false, details: [ `Mask has no hashinfo` ] };
  }
  if (!original) {
    trace(`#verify: no original passed`);
    return { valid: false, match: false, details: [ `Original is null` ] };
  }
  if (!nonce) {
    trace(`#verify: no nonce passed`);
    return { valid: false, match: false, details: [ `Nonce is null` ] };
  }
  const valid = true;
  const details = [];

  const ohash = tsig.hashJSON({original,nonce});
  details.push(`Comparing nonce-d original hash to (${JSON.stringify(ohash)}) to mask hash (${JSON.stringify(mask.hashinfo)})`);
  trace('#verify: '+details[details.length-1]); // print that message
  const match = _.isEqual(mask.hashinfo, ohash);

  return {valid,match,details};
}

// verifyRemote: verify a single mask object, fetching the remote original to verify
//   mask: the masked object.  Required.
//  token: string token.  Optional if you pass connection.
//  connection: OADA cache connection.  Optional if you pass token
//
// Returns: 
//   - valid: true|false same as verify()
//   - match: true|false same as verify()
//   - original: the fetched original
//   - details: helpful array of debugging strings
// NOTE: you must pass either token or a connection.  The assumption is that the nonce and URL are at the same cloud.
async function verifyRemote({mask, token, connection}) {
  if (mask && mask['trellis-mask']) {
    mask = mask['trellis-mask'];
  }
  if (!mask.url) {
    trace('#verifyRemote: mask has no url');
    return { valid: false, match: false, original: false, nonce: false, details: [ 'The mask has no url' ] };
  }
  const domain = domainFromURL(mask.url);
  connection = await connectionOrToken({token: (token ? token : false), connection: (connection ? connection : false), domain});

  details = [];
  trace('#verifyRemote: Requesting original and nonce from remote');
  const { original, nonce } = await Promise.props({
    original: connection.get({ path: pathFromURL(mask.url) }).then(r => r.data)
              .catch(e => { details.push(`Failed to retrieve original.  Error was: ${JSON.stringify(e)}`); return null; }),
       nonce: connection.get({ path: pathFromURL(mask.nonceurl) }).then(r => r.data)
              .catch(e => { details.push(`Failed to retrieve nonce.  Error was: ${JSON.stringify(e)}`);    return null; }),
  })
  if (!original || !nonce) {
    warn(`#verifyRemote: failed original (${original}) or nonce (${nonce}). Details = `,details);
    return { valid: false, match: false, original: false, nonce: false, details };
  }

  trace('#verifyRemote: retrieved original (',original,') and nonce, sending to verify');
  const result = verify({mask, original, nonce}); // returns { valid, match, details }
  return { 
    valid: result.valid, 
    match: result.match, 
    original,
    nonce,
    details: details.concat(result.details) 
  };
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
// Functions for dealing with entire resources containing multiple masks
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//------------------------------------------------------------------------------

// Given a resource and a private key, this will use trellisfw-signatures 
// to add a new signature to the document of type `mask`.  This does not
// mutate the resource, but rather returns the new resource with the signature.
// If you do not pass header, it will create the appropriate jwk, kid, jku for you
// from the privateJWK.  You should pass a signer as { name: 'Name of signer', url: 'https://their.domain' }
// resource: JSON object to sign
// privateJWK: a jwk to sign with
// signer: { name, url } => passed to trellisfw-signatures
// header: any additional headers to pass to trellisfw-signatures
// paths: array of json pointers of which paths in the main resource were masked in this round
//        [ 'a/b', 'b/d/e', 'c' ], etc.
// NOTE: this does not mutate resource, but returns new signed version
async function signResource({resource, privateJWK, header, signer, paths }) {
  signer = signer || { name: 'No signer name available', url: 'https://github.com/trellisfw' },
  header = header || {};
  if (!header.jwk) {
    trace('#signResource: did not pass header.jwk, extracting from private key');
    header.jwk = tsig.keys.pubFromPriv(privateJWK);
  }
  if (!header.kid) {
    trace('#signResource: did not pass header.kid, extracting from private key');
    header.kid = privateJWK.kid;
  }
  if (!header.jku) {
    trace('#signResource: did not pass header.jku, extracting from private key');
    header.jku = privateJWK.jku;
  }
  const payload = {};
  if (paths) {
    trace('#signResource: adding paths to signature: ', paths);
    payload['mask-paths'] = paths;
  }
  resource = await tsig.sign(resource, privateJWK, { signer, type: 'mask', payload });
  trace('#signResource: signed resource, signature is: ', resource.signatures[resource.signatures.length-1]);
  return resource;
}


// Given an entire resource with one or more paths to mask, create a single nonce and
// mask all the json pointer paths with that nonce.  Note that this does not fetch 
// the resource at the URL, it just uses that URL to construct the paths.
// Assumes that you want to put the nonce at <urlToResource>/_meta/nonce
function maskResource({resource, urlToResource, paths, nonce, nonceurl}) {
  const r = _.cloneDeep(resource);
  if (!urlToResource) {
    warn('#maskResource: urlToResource is falsey, you need to pass one in order to figure out url\'s from paths');
    return { nonce: false, resource: false, nonceurl: false };
  }
  nonce = nonce || makeNonce();
  nonceurl = nonceurl || urlToResource+'/_meta/nonce';
  _.each(paths, p => {
    // get the thing to mask:
    const objToMask = jsonpointer.get(resource, p);
    trace(`#maskResource: tried to jsonpoint.get path ${p} from resource, it returned `,objToMask);
    // construct the mask:
    const result = mask({original: objToMask, nonce, url: urlToResource+p, nonceurl });
    // replace the thing in the original with the mask
    trace(`#maskResource: setting path ${p} in resource to mask = `, result.mask);
    jsonpointer.set(r, p, result.mask);
  });
  return { nonce, resource: r, nonceurl };
}

// This creates a new resource on the OADA cloud that is a masked version of the original.
// It does not modify the original, except that it stores the nonce at the original's _meta/nonce
async function maskRemoteResourceAsNewResource({ url, paths, token, connection, signatureCallback }) {
  if (!url) {
    error('#maskRemoteResourceAsNewResource: you must pass a url');
    throw new Error('#maskRemoteResourceAsNewResource: you must pass a url to mask');
  }
  if (!paths || paths.length < 1) {
    error('#maskRemoteResourceAsNewResource: you must pass at least one path to mask in the resource');
    throw new Error('#maskRemoteResourceAsNewResource: you must pass at least one path to mask in the resource');
  }
  const domain = domainFromURL(url);
  const path = pathFromURL(url);
  connection = await connectionOrToken({token: (token ? token : false), connection: (connection ? connection : false), domain});

  trace('#maskRemoteResourceAsNewResource: Requesting original from remote and creating new empty resource for our copy');
  const original = await connection.get({ path })
    .then(r => r.data)
    .catch(e => { throw new Error(`Could not get original resource at url ${url}.  Error was: ${e}`) });
  trace('#maskRemoteResourceAsNewResource: retrieved original, it is',original);

  // If we already have a nonce on the resource, use that instead of overwriting
  const nonceurl = url + '/_meta/nonce';
  let nonce = null;
  let havenonce = false;
  await connection.get({ path: pathFromURL(nonceurl) })
  .then(r => {
    trace('#maskRemoteResourceAsNewResource: original already has a nonce, re-using that');
    nonce = r.data;
  }).catch(async (e) => {
    trace('#maskRemoteResourceAsNewResource: original does not have a nonce, making a new one and saving to '+pathFromURL(nonceurl));
    nonce = makeNonce();
    await connection.put({ path: pathFromURL(nonceurl), data: JSON.stringify(nonce), headers: { 'content-type': original._type } })
          .catch(e => { throw new Error(`Could not save new nonce back to original resource!  error was ${e}`) });
  });

  trace('#maskRemoteResourceAsNewResource: masking Resource content locally with maskResource');
  let { resource } = maskResource({resource: original, urlToResource: url, paths, nonce, nonceurl});

  // If you want to sign it, now is a good time
  if (signatureCallback) {
    trace('#maskRemoteResourceAsNewResource: calling signatureCallback');
    resource = await signatureCallback(resource);
  }

  // Now, put the resource back as the copy
  const newResource = 
    await connection.post({ path: `/resources`, data: resource, headers: { 'content-type': original._type } })
                    .then(r => r.headers['content-location'].slice(1)) // get rid of leading slash for _id
                    .catch(err => { throw new Error(`Could not PUT masked resource into new resource copy.  Error was: '${err}`) });

  return newResource; // return the id of the new resource that is the masked version
}


// This makes a masked copy of a resource with the given paths masked, and it also
// re-signs the masked document after masking
async function maskAndSignRemoteResourceAsNewResource({url, privateJWK, signer, token, connection, paths}) {
  token = token || false;
  connection = connection || false;
  return await maskRemoteResourceAsNewResource({
    url, signer, token, connection, paths, 
    signatureCallback: async (resource) => 
      await signResource({resource,privateJWK, signer, paths}) // returns the signed version of resource to maskRemoteResourceAsNewResource
  });
}


// Given a set of paths, reconstruct those paths in the original resource from the masks that are there.
async function reconstructOriginalFromMaskPaths(maskedResource, paths, connection) {
  const result = await Promise.map(paths, async (p) => {
    const mask = jsonpointer.get(maskedResource,p);
    trace('#reconstructOriginalFromMaskPaths: retrieved path ',p,' from maskedResource and got mask = ', mask);
    const { valid, match, original, details } = await verifyRemote({mask,connection}); // valid, match, original, details
    return { path: p, valid, match, original, details };
  }).reduce((acc,p) => {
    acc.details.push(`Path ${p.path}: valid = ${p.valid}, match = ${p.match}, details = ${JSON.stringify(p.details)}`);
    jsonpointer.set(acc.resource, p.path, p.original);
    return {
      valid: acc.valid && p.valid,
      match: acc.match && p.match,
      details: acc.details,
      resource: acc.resource,
    };
  }, { valid: true, match: true, details: [], resource: maskedResource });
  return result;
}

// This can take url to a masked resource and token or connection, and verify all the
// masks inside it as well as reconstruct it and verify all the mask signatures in order
// until it finds a non-mask signature.
// returns { 
//   trusted: true|false => is signature by a trusted signer
//   valid: true|false => are all masks valid AND all mask signatures are valid, 
//   unchanged: true|false => is original document unchanged since signature was applied, 
//   match: true|false => do ALL mask hashes match the original
//   details: array of strings to help you debug
// }
// IMPORTANT NOTE: This does not yet support modification signatures, only masks and other non-modifying types.
async function verifyRemoteResource({url, token, connection}) {
  const domain = domainFromURL(url);
  const path = pathFromURL(url);
  connection = await connectionOrToken({token: (token ? token : false), connection: (connection ? connection : false)});

  const maskedResource = await connection.get({path: pathFromURL(url)}).then(r => r.data)
                               .catch(e => { throw new Error(`Failed to retrieve masked resource from path ${pathFromURL(url)}.  Error was: ${e}`) });
  trace('#verifyRemoteResource: retrieved masked resource, signatures = ', maskedResource.signatures);

  // First, verify the signature so we can get the mask-paths from that
  async function recursiveVerifyMaskSignatures(resource) {
    // If there is no signature, then unchanged and trusted must be false
    let sigResult = { unchanged: false, trusted: false, match: true, valid: true, original: resource, details: [ 'No signature on resource' ]};
    if (resource.signatures) {
      sigResult = await tsig.verify(resource);
    }
    const { payload } = sigResult;
    if (!sigResult.valid) {
      trace('#recursiveVerifyMaskSignatures: signature is invalid, aborting');
      return { valid: false, match: false, unchanged: false, resource: sigResult.original, details: [ 'Signature is invalid' ] };
    }

    let reconstructResult = { valid: sigResult.valid, match: true, unchanged: true, resource: sigResult.original, details: [] };
    if (payload) {
      if (payload.type === 'mask') {
        trace('#recursiveVerifyMaskSignatures: found mask signature, reconstructing...');
        // Reconstruct the original at this point by replacing each path from payload.mask-paths, also checking each mask as we go:
        reconstructResult = await reconstructOriginalFromMaskPaths(sigResult.original, payload['mask-paths'], connection);
      } else if (payload.type === 'modification') {
        error('#verifyRemoteResource: modification signatures are not supported yet.  That feature needs to be added and rework this to play nicer with tsig by supplying tsig with a function it can use to reconstruct/validate a single mask signature');
        throw new Error('#verifyRemoteResource: modifiation signature are not supported yet.');
      }
    } // If no payload, then there wasn't a signature at all

    // Now the original should be reconstructed, if there is still a signature we can ask for that
    // one's result:
    let nextRound = { trusted: true, valid: true, unchanged: true, match: true, details: [], original: reconstructResult.resource};
    if (reconstructResult.resource.signatures) {
      nextRound = await recursiveVerifyMaskSignatures(reconstructResult.resource);
    }

    // trace('Returning combination of sigResult: ', sigResult, ', nextRound: ', nextRound, ', and reconstructResult: ', reconstructResult);
    // Return a combination of this round, all the mask matches, and the next round's result
    return { 
        trusted: sigResult.trusted   && nextRound.trusted,
      unchanged: sigResult.unchanged && nextRound.unchanged, 
          valid: sigResult.valid     && nextRound.valid      && reconstructResult.valid,
          match:                        nextRound.match      && reconstructResult.match,
       original: nextRound.original,
        details: sigResult.details.concat(reconstructResult.details).concat(nextRound.details) 
    };
  }

  const { trusted, unchanged, valid, match, original, details } = await recursiveVerifyMaskSignatures(maskedResource);
  const paths = findAllMaskPathsInResource(original);
  details.push('After verifying signatures, these mask paths remained in resource: ', JSON.stringify(paths));
  trace('#verifyRemoteResource: after verifying signatures, these mask paths remain in resource: ', paths);
  if (!paths || paths.length < 1) {
    return { trusted, unchanged, valid, match, original, details };
  }
  // Otherwise, we need to reconstruct these and merge:
  const reconstructResult = await reconstructOriginalFromMaskPaths(original, paths, connection);
  return {
    trusted,
    unchanged, 
    match: match && reconstructResult.match,
    valid: valid && reconstructResult.valid,
    original: reconstructResult.resource,
    details: details.concat(reconstructResult.details),
  };
}

module.exports = {
  // Dealing with individual objects to mask:
  mask,   // sync, only local
  verify, // sync, only local
  verifyRemote, // async, fetches outside

  // Dealing with entire resources:
  maskResource, // sync, only local
  signResource, // async, only local
  maskRemoteResourceAsNewResource,        // async, talks outside
  maskAndSignRemoteResourceAsNewResource, // async, talks outside
  verifyRemoteResource,                   // async, talks outside

  // Handy functions:
  isMask,                     // sync
  domainForMask,              // sync
  findAllMaskPathsInResource, // sync
};
