// Credential records as this browser saved them before Phase 23: the server's
// storedCredential from register-complete (characterization goldens of
// 2026-09-25, simple-register-packed-x5c-extensions and
// advanced-register-packed-x5c-everything), with standard base64 in the
// fields it did not label. Copied here, not read from the goldens, which now
// hold base64url.

export const SIMPLE_RECORD = {
  "type": "simple",
  "email": "user@example.com",
  "userName": "user@example.com",
  "displayName": "user@example.com",
  "credentialId": "FPhff9VVh1/mDEjMl0iusO+dKpqIUox+/4tcBas7neE=",
  "credentialIdBase64Url": "FPhff9VVh1_mDEjMl0iusO-dKpqIUox-_4tcBas7neE",
  "credentialIdHex": "14f85f7fd555875fe60c48cc9748aeb0ef9d2a9a88528c7eff8b5c05ab3b9de1",
  "aaguid": "ABEiM0RVZneImaq7zN3u_w",
  "aaguidHex": "00112233445566778899aabbccddeeff",
  "publicKey": "pQECAyYgASFYIOLs+Xt6EYyV+lFHdJ43X/SjqXCOpIw73cDjX2SUP4dMIlggA5n2XLQj1d7AUqvEcKAgDvrRqdJzrR99F9NdsmjB/xs=",
  "publicKeyBase64Url": "pQECAyYgASFYIOLs-Xt6EYyV-lFHdJ43X_SjqXCOpIw73cDjX2SUP4dMIlggA5n2XLQj1d7AUqvEcKAgDvrRqdJzrR99F9NdsmjB_xs",
  "publicKeyAlgorithm": -7,
  "publicKeyBytes": "pQECAyYgASFYIOLs+Xt6EYyV+lFHdJ43X/SjqXCOpIw73cDjX2SUP4dMIlggA5n2XLQj1d7AUqvEcKAgDvrRqdJzrR99F9NdsmjB/xs=",
  "publicKeyCose": {
    "-3": "A5n2XLQj1d7AUqvEcKAgDvrRqdJzrR99F9NdsmjB/xs=",
    "-2": "4uz5e3oRjJX6UUd0njdf9KOpcI6kjDvdwONfZJQ/h0w=",
    "-1": 1,
    "1": 2,
    "3": -7
  },
  "signCount": 0,
  "attestationFormat": "packed",
  "attestationStatement": {
    "alg": -7,
    "sig": "MEQCIEZ1L8aEroaidBeW3olMX7L40gXum3cwIP6C+67xSoESAiBxs1BzKjh71rsPpurSuC7YIK0YihBJwK2WcNQo+U0EYw==",
    "x5c": [
      "MIIBtDCCAWagAwIBAgICHq8wBQYDK2VwMCMxITAfBgNVBAMMGENoYXJhY3Rlcml6YXRpb24gVGVzdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MTIzMTAwMDAwMFowfTELMAkGA1UEBhMCU0UxHjAcBgNVBAoMFUNoYXJhY3Rlcml6YXRpb24gVGVzdDEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEqMCgGA1UEAwwhQ2hhcmFjdGVyaXphdGlvbiBBdHRlc3RhdGlvbiBMZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZBoo8EShnYtAg7HcnNArsKmvundF5ndTJe06OX2xiC8zT1B2FQcOxykxFXDPSzKd5ER60LnCSL/3BrGuW9chxqMzMDEwDAYDVR0TAQH/BAIwADAhBgsrBgEEAYLlHAEBBAQSBBAAESIzRFVmd4iZqrvM3e7/MAUGAytlcANBAJfvyLEWLdbGJ62qXdTTLZgz1xp0LYWpm/j8W5/u3PBSl1nUVLoQPfZS+6B+xESrUzwWA2mrVRGy2Ni8M39znAc="
    ]
  },
  "clientExtensionOutputs": {
    "credProps": {
      "rk": true
    },
    "largeBlob": {
      "supported": true
    },
    "minPinLength": 8
  },
  "userHandle": "dXNlckBleGFtcGxlLmNvbQ"
};

export const ADVANCED_RECORD = {
  "type": "advanced",
  "userName": "user@example.com",
  "displayName": "A. User",
  "credentialId": "HhfJJzOBVmmUZYuGYc2aY9SMJiNMjQ1Y0QppVmqI4yI",
  "credentialIdBase64Url": "HhfJJzOBVmmUZYuGYc2aY9SMJiNMjQ1Y0QppVmqI4yI",
  "credentialIdHex": "1e17c9273381566994658b8661cd9a63d48c26234c8d0d58d10a69566a88e322",
  "aaguid": "ABEiM0RVZneImaq7zN3u_w",
  "aaguidHex": "00112233445566778899aabbccddeeff",
  "publicKey": "pQECAyYgASFYIOEwuXhv8VDNwRWr+lvZyR3c4huUqfFJxMdFv2eGhEsvIlggtDdm4OvKPMpcRN7orExKgJjWk6IogLbfU/fHAyrN0uc=",
  "publicKeyBase64": "pQECAyYgASFYIOEwuXhv8VDNwRWr+lvZyR3c4huUqfFJxMdFv2eGhEsvIlggtDdm4OvKPMpcRN7orExKgJjWk6IogLbfU/fHAyrN0uc=",
  "publicKeyBase64Url": "pQECAyYgASFYIOEwuXhv8VDNwRWr-lvZyR3c4huUqfFJxMdFv2eGhEsvIlggtDdm4OvKPMpcRN7orExKgJjWk6IogLbfU_fHAyrN0uc",
  "publicKeyAlgorithm": -7,
  "publicKeyCose": {
    "-1": 1,
    "-2": "4TC5eG/xUM3BFav6W9nJHdziG5Sp8UnEx0W/Z4aESy8=",
    "-3": "tDdm4OvKPMpcRN7orExKgJjWk6IogLbfU/fHAyrN0uc=",
    "1": 2,
    "3": -7
  },
  "publicKeyType": 2,
  "signCount": 0,
  "userHandle": "dXNlci1oYW5kbGU=",
  "userHandleBase64": "dXNlci1oYW5kbGU=",
  "userHandleBase64Url": "dXNlci1oYW5kbGU",
  "userHandleHex": "757365722d68616e646c65",
  "clientExtensionOutputs": {
    "credProps": {
      "rk": false
    },
    "largeBlob": {
      "written": true
    },
    "minPinLength": 6,
    "prf": {
      "enabled": true
    }
  },
  "storageId": "HhfJJzOBVmmUZYuGYc2aY9SM::1a0c4506c00::02f5575ac1c848f2bfd09f36c6fe1da5",
  "id": "HhfJJzOBVmmUZYuGYc2aY9SMJiNMjQ1Y0QppVmqI4yI"
};
