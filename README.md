# trellisfw-masklink

Library for performing Mask & Link operations.  

## Overview
---------------------
When you have information in a JSON document that you do not want to
share with someone, but you need to share the rest of the document, 
you can replace the sensitive information with a auditable `trellis-mask`.

In addition to replacing the original information, you can sign the document
as an added layer of trust.  The signature contains information about which
keys were masked, allowing anyone with access to the unmasked original to 
verify both the signatures and the masks whenever an audit is necessary.

For example, if this is your _unmasked_ document:
```javascript
{
  phone: "999-999-9999",
  location: { // This location is sensitive information
    street_address: "123 Nowhere Lane",
    city: "Nowhere",
    state: "FL",
    zip: "99999"
  }
}
```

And you want to _mask_ the `location` key, the _masked_ version would look like:
```javascript
{ 
  phone: "999-99-9999",
  location: {

    // See the contents here have been replaced by an object with a hash and a link:
    "trellis-mask": {
      version: "1.0",
      hashinfo: {
        alg: "SHA256",
        hash: "02fjkdofj213oikjwdo0fi2jfpiwjsdc029u3f0923uj23oiesls",
      },
      "url": "https://some.trellis.domain/resources/the_original_resourceid/location",
      "nonceurl": "https://some.trellis.domain/resource/the_original_resourceid/_meta/nonce",
    },
  },

  // A trellisfw-signature can be applied during masking to add another layer of trust
  signatures: [
    "ejfkdo9fk234.k0f2jik2lfjafwe9oifjlwjhqi3fwlakefjaowkefu02ijfklsafjwasdf.dkfj23",
  ],
}
```


## API for Masked Objects (not full documents)
-------------------------------------------------

### `mask({ original, url, nonce, nonceurl })` _synchronous_
* `original`: _required_: the object to be hashed and masked
* `url`: _required_: the remote URL where this object would be found at a Trellis domain, including the path to this object inside a resource.
* `nonceurl`: _required_: the URL where the nonce can be retrieved by someone trying to validate this hash later.
* `nonce`: _optional_: if you don't pass a nonce, one will be created for you.  Note you have to save it somewhere...
Note this function makes no outside requests, it only creates the mask.

Returns `{ nonce, nonceurl, mask }`

```javascript
const { nonce, nonceurl, mask } = mask({original, url, nonceurl});
console.log('Mask = ', mask);
// { trellis-mask: { version: "1.0", hashinfo: { alg: "SHA256", hash: "02ijd0fijk2lfwd" }, nonceurl, url } }
```

### `verify({mask, original, nonce})` _synchronous_
* `mask`: _required_: the masked object to be verified
* `original`: _required_: the original unmasked object to hash and compare with the mask
* `nonce`: _required_: the nonce used to create the original mask
Note: this function makes no outside requests, it only validates based on what it is given.

Returns `{ valid, match, details }`
* `valid`: `true|false`: true if mask, original, and nonce have valid forms, but says nothing about whether they match.
* `match`: `true|false`: true if hash inside mask matches original w/ nonce.
* `details`: `array`: array of strings about the matching process to aid in debugging


### `async verifyRemote({mask, token, connection})`
Given a mask, retrieve the original at `mask.url` and the nonce at `mask.nonceurl` and then pass to `verify`
* `mask`: _required_: the original masked object to be validated against it's internal remote URL's
* `token`: _optional_: the token to use when connecting to the remote URL
* `connection`: _optional_: a pre-existing [oada-cache](https://github.com/oada/oada-cache) connection to the remote URL
NOTE: you must pass either a connection or a token so the function can make the necessary requests.

Returns `{ valid, match, original, nonce, details }`
* `valid`: `true|false`: true if mask, original, and nonce have valid forms, but says nothing about whether they match.
* `match`: `true|false`: true if hash inside mask matches original w/ nonce.
* `original`: the original unmasked object that was retrieved from `mask.url`
* `nonce`: the nonce that was retrieved from `mask.nonceurl`
* `details`: `array`: array of strings about the matching process to aid in debugging


## API for Full Documents Containing Masks
---------------------------------------------
### `maskResource({ resource, urlToResource, paths, nonce, nonceurl })` _synchronous_
Given an entire JSON document, use the list of json-pointer paths to mask some of its contents.
* `resource` _required_: the original resource to be masked
* `urlToResource` _required_: where this resource was stored, to be used in the mask url's
* `paths` _required_: array of json-pointer paths to mask within this resource (i.e. `[ 'organization/location' ]`)
* `nonce` _optional_: nonce to use in hashing.  If you don't pass it, one is created.
* `nonceurl` _optional_: where the nonce will be stored.  Assumed `<urlToResource>/_meta/nonce` if not passed.
NOTE: this function is entirely local, it makes no outside requests.

Returns `{ nonce, resource, nonceurl }`
* `nonce`: the nonce used (either passed or created)
* `resource`: the final resource after masking the paths
* `nonceurl`: the nonceurl to store the nonce (either passed or created)


### _async_ `signResource({resource, privateJWK, header, signer, paths})`
Creates a `mask`-type signature on a resource using the [trellisfw-signatures](https://github.com/trellisfw/trellisfw-signatures).
* `resource`: A resource that has already had masks applied to it that correspond to `paths`.
* `privateJWK`: A JWK that is the private key used to create the JWT signature
* `header` _optional_: any additional headers to pass to [trellisfw-signatures](https://github.com/trellisfw/trellisfw-signatures)
* `signer` _optional_: Object describing who is signing.  Looks like `{ name: "The Signing Company", url: "https://domain.com" }`
* `paths` _optional_: Array of json-pointer paths that were masked in `resource` corresponding with this signature.

Returns `resource` (a new copy of the resource with the signature added)


### _async_ `maskRemoteResourceAsNewResource({url, paths, token, connection, signatureCallback})`
* `url` _required_: The URL where the original resource to mask can be found
* `paths` _required_: List of json-pointer paths into the original resource that should be signed.
* `token` or `connection` _required_: Pass either a token or an [oada-cache](https://github.com/oada/oada-cache) connection to use in getting the original and putting back the mask.
* `signatureCallback` _optional_: If you want to apply a signature after masking, pass it here and it will be called after masking before creating the new masked resource at the remote URL.

Returns `newResourceid` (the ID of the new resource on the remote cloud, looks like `resources/02ikefj092jlkdss`)


### _async_ `maskAndSignRemoteResourceAsNewResource({url, privateJWK, signer, token, connection, paths})`
Given a remote URL, make a masked copy, sign it with the given key, and put it back to the remote cloud.  Mostly a wrapper for `maskRemoteResourceAsNewResource` and `signResource`.
Refer to `signResource` and `maskRemoteResourceAsNewResource` for an explanation of the parameters.

Returns `newResourceid` (the ID of the new resource on the remote cloud, looks like `resources/02ikefj092jlkdss`)


### _async_ `verifyRemoteResource({url, token, connection})`
Given a remote URL for a masked resource, get it, reconstruct it from the signatures, and verify every masked object along the way.  Note this will verify _all_ signatures present on the document, not just the last one.

* `url` _required_: URL of the remote masked resource that you want to verify
* `token` or `connection` _required_: Pass either a token or an [oada-cache](https://github.com/oada/oada-cache) connection to use in getting the mask and the original.  Note that currently it uses the same for both the mask and original.  Future feature add would be to allow those to be different.

Returns `{ trusted, unchanged, valid, match, original, details }`
* `trusted`: `true|false`: Same as the `trusted` return value from [trellisfw-signatures](https://github.com/trellisfw/trellisfw-signatures).  Indicates that the signature came from a key that is represented on the trusted list.
* `unchanged`: `true|false`: true if the reconstruction matches the signatures (i.e. it was unchanged since signing)
* `valid`: `true|false`: true if all the signtures and all the masks they reference in the document have valid forms.  Does not tell you if they are unchanged or if the masks match the original.
* `match`: `true|false`: true if all masks mentioned in signatures match their originals
* `original`: the full original resource, reconstructed from the signatures and mask originals
* `details`: array of strings with messages about the verification process, useful for debugging.


## Exposed Helper Functions
---------------------------------------------
### `isMask(obj)` _synchronous_
Returns `true` if `obj` has all the appropriate keys to be a trellis-mask.

### `domainForMask(mask)` _synchronous_
Returns the domain portion of the url found within the mask.  Note that it ignores the nonceurl.

### `findAllMaskPathsInResource(resource)` _synchronous_
Returns an array of json-pointer strings, containing every path whose value returns `true` for `isMask()` within the passed `resource`
```javascript
const paths = findAllMaskPathsInResource(resource);
console.log(paths);
// [ 'organization/location', 'scope/organization/location' ]
```
