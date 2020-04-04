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
}```

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
}```


## API for Masked Objects (not full documents)
-------------------------------------------------

### `mask()`
### `verify()`
### verifyRemote


## API for Full Documents Containing Masks
---------------------------------------------
### maskResource, // sync, only local
### signResource, // async, only local
### maskRemoteResourceAsNewResource,        // async, talks outside
### maskAndSignRemoteResourceAsNewResource, // async, talks outside
### verifyRemoteResource,                   // async, talks outside



## Exposed Helper Functions
---------------------------------------------
### isMask
### domainForMask
### findAllMaskPathsInResource
