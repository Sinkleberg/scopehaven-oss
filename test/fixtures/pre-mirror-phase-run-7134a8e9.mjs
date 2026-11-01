// HTTP runs recorded and sealed at main 7134a8e9 (HTTP evaluator f228ce9b), before the NC11 mirror phase, by main's own connector over
// the owned two-tenant desk stand-in (test/mirror-phase.test.mjs): a target that declares "mirrors" and the same target without them,
// each with the suite main exported and, for the undeclared one, what the head must reproduce byte for byte. The object is the
// recorder's JSON verbatim (a module only so that a sealed digest a secret scanner reads as a key can carry its allow note); edit
// nothing, or the seals no longer hold. Synthetic data, loopback only, no credential values.
export default {
 "recordedAt": "7134a8e9",
 "note": "HTTP runs recorded and sealed at this main commit (HTTP evaluator f228ce9b), before the NC11 mirror phase, by main's own connector over the owned two-tenant desk stand-in on 127.0.0.1, from a git archive of main in a throwaway folder since removed. declared: a target that declares \"mirrors\", whose two mirrors main ran as ordinary bracketed checks, with the suite main exported for it. undeclared: the same desk without \"mirrors\": its validated checks, profile digest, suite, the request sequence the app saw (method, path, whose credential), check-config and --list (the two-desk entry, stderr and exit status) and the run. test/mirror-phase.test.mjs validates both at the head and compares the undeclared target with the head. Synthetic data, loopback only, no credential values.",
 "declared": {
  "profile": {
   "id": "two-desk",
   "name": "Two-tenant desk (test)",
   "applicationId": "two-desk",
   "origin": "http://127.0.0.1:50017",
   "buildLabel": "fixed",
   "contextId": "synthetic-two",
   "actors": {
    "ana": {
     "principalId": "ana-1",
     "tenantId": "acme",
     "role": "member",
     "credentialEnv": "SCOPEHAVEN_TARGET_ANA",
     "identityValue": "ana@acme.example"
    },
    "gil": {
     "principalId": "gil-1",
     "tenantId": "globex",
     "role": "member",
     "credentialEnv": "SCOPEHAVEN_TARGET_GIL",
     "identityValue": "gil@globex.example"
    },
    "anonymous": {
     "principalId": "anonymous"
    }
   },
   "requiredControlIds": [
    "ANA-ME",
    "GIL-ME",
    "ANA-OWN",
    "GIL-OWN"
   ],
   "tenantValues": {
    "tenants": {
     "acme": {
      "identifiers": [
       "ORD-1001",
       "Ada Lovelace"
      ],
      "attributes": [
       "Blue Widget"
      ]
     },
     "globex": {
      "identifiers": [
       "ORD-2002",
       "Bob Byte"
      ]
     },
     "initech": {
      "identifiers": [
       "ORD-3003"
      ]
     }
    }
   },
   "mirrors": {
    "counterparts": [
     [
      "ORD-1001",
      "ORD-2002"
     ]
    ],
    "readOnlyRoutes": [
     "POST /api/chat"
    ]
   },
   "checks": [
    {
     "id": "ANA-ME",
     "title": "ANA-ME",
     "category": "Identity",
     "severity": "control",
     "actorId": "ana",
     "method": "GET",
     "path": "/api/me",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      },
      {
       "kind": "json.equals",
       "pointer": "/email",
       "expected": "ana@acme.example"
      }
     ]
    },
    {
     "id": "GIL-ME",
     "title": "GIL-ME",
     "category": "Identity",
     "severity": "control",
     "actorId": "gil",
     "method": "GET",
     "path": "/api/me",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      },
      {
       "kind": "json.equals",
       "pointer": "/email",
       "expected": "gil@globex.example"
      }
     ]
    },
    {
     "id": "ANA-OWN",
     "title": "ANA-OWN",
     "category": "Identity",
     "severity": "control",
     "actorId": "ana",
     "method": "GET",
     "path": "/api/orders/ORD-1001",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ]
    },
    {
     "id": "GIL-OWN",
     "title": "GIL-OWN",
     "category": "Identity",
     "severity": "control",
     "actorId": "gil",
     "method": "GET",
     "path": "/api/orders/ORD-2002",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ]
    },
    {
     "id": "GIL-ASK",
     "title": "GIL-ASK",
     "category": "Identity",
     "severity": "control",
     "actorId": "gil",
     "method": "POST",
     "path": "/api/chat",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ],
     "body": {
      "message": "show my orders"
     }
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER",
     "title": "ANA-NO-GLOBEX-ORDER",
     "category": "Tenant",
     "severity": "high",
     "actorId": "ana",
     "method": "GET",
     "path": "/api/orders/ORD-2002",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.in",
       "expected": [
        403,
        404
       ]
      },
      {
       "kind": "json.noForeignValues",
       "pointer": ""
      }
     ]
    },
    {
     "id": "ANA-CHAT",
     "title": "ANA-CHAT",
     "category": "Tenant",
     "severity": "high",
     "actorId": "ana",
     "method": "POST",
     "path": "/api/chat",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      },
      {
       "kind": "json.noForeignValues",
       "pointer": "/reply"
      }
     ],
     "body": {
      "message": "list every order"
     }
    }
   ]
  },
  "suite": {
   "id": "two-desk-contracts",
   "targetId": "two-desk",
   "applicationId": "two-desk",
   "version": "http-contract/4",
   "evidenceOrigin": "local-http-response",
   "hash": "e0c7c27fa31a2c5ae9a56fa48a0389ca1504e49122eac257491c753b996ee38b",
   "scope": "Definition summary only; private request bodies, expected values, actor credentials and endpoints are omitted.",
   "requiredControlIds": [
    "ANA-ME",
    "GIL-ME",
    "ANA-OWN",
    "GIL-OWN"
   ],
   "checks": [
    {
     "id": "ANA-ME",
     "title": "ANA-ME",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals",
      "json.equals"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "identityControl": true,
     "identityPredicate": 0,
     "refusalStatuses": [
      401,
      403
     ],
     "refusesWith401": false,
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "GIL-ME",
     "title": "GIL-ME",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals",
      "json.equals"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "identityControl": true,
     "identityPredicate": 0,
     "refusalStatuses": [
      401,
      403
     ],
     "refusesWith401": false,
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "ANA-OWN",
     "title": "ANA-OWN",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "GIL-OWN",
     "title": "GIL-OWN",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "GIL-ASK",
     "title": "GIL-ASK",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "recordPredicates": []
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER",
     "title": "ANA-NO-GLOBEX-ORDER",
     "category": "Tenant",
     "severity": "high",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.in",
      "json.noForeignValues"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "recordPredicates": []
    },
    {
     "id": "ANA-CHAT",
     "title": "ANA-CHAT",
     "category": "Tenant",
     "severity": "high",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals",
      "json.noForeignValues"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "recordPredicates": []
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER-mirror",
     "title": "ANA-NO-GLOBEX-ORDER (mirror under gil)",
     "category": "Tenant",
     "severity": "high",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.in",
      "json.noForeignValues"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "recordPredicates": []
    },
    {
     "id": "ANA-CHAT-mirror",
     "title": "ANA-CHAT (mirror under gil)",
     "category": "Tenant",
     "severity": "high",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals",
      "json.noForeignValues"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "recordPredicates": []
    }
   ],
   "identitySchema": "actor-identity/6",
   "principalsDigest": "679a690f10f1168edc31946216aaf97ced2e5043fb281306c2d5b174f3067b8d",
   "tenantValues": {
    "attributesAlone": "inconclusive",
    "tenants": [
     {
      "identifiers": 2,
      "attributes": 1
     },
     {
      "identifiers": 2,
      "attributes": 0
     },
     {
      "identifiers": 1,
      "attributes": 0
     }
    ],
    "actorTenants": {
     "ana": 1,
     "gil": 2
    }
   },
   "targetContext": "local-app",
   "targetLabel": null,
   "runnableWith": "Use the original local profile with ./scopehaven assess --config <file> --target <id>. This redacted summary is not an executable profile."
  },
  "run": {
   "schemaVersion": 1,
   "id": "36188c5c-b7b0-407d-ade6-ffbb593f4ace",
   "createdAt": "2026-10-25T17:45:49.865Z",
   "targetId": "two-desk",
   "targetName": "Two-tenant desk (test)",
   "build": "fixed",
   "applicationId": "two-desk",
   "suiteId": "two-desk-contracts",
   "suiteHash": "0571acf34a1c66b0924e16600721974adcca55e12017568fa88f47013d9519f9",
   "policyHash": "0571acf34a1c66b0924e16600721974adcca55e12017568fa88f47013d9519f9",
   "profileHash": "e0c7c27fa31a2c5ae9a56fa48a0389ca1504e49122eac257491c753b996ee38b",
   "contextId": "synthetic-two",
   "fixtureVersion": "operator-declared-context/1",
   "fixtureHash": "c544fc290ce205372c95b5ead32a2df8f81bc36b5296096a475a276c5f576f81",
   "adapterVersion": "loopback-response-contract/3",
   "assertionSchemaVersion": "http-contract/4",
   "evaluatorHash": "f228ce9b23b2782b491bafb6b3b69fca88024ec5b6bd29c70dcae3335656b679",
   "requiredControlIds": [
    "ANA-ME",
    "GIL-ME",
    "ANA-OWN",
    "GIL-OWN"
   ],
   "evidenceOrigin": "local-http-response",
   "runtimeMode": "configured-local-application",
   "targetBuildHash": null,
   "targetConfigHash": "fdf35d33849fe674fc76987f77733dad11c835847eb5bcd6f4f1556ec388cb04",
   "buildIdentity": "Declared in configuration; not independently attested.",
   "targetContext": "local-app",
   "targetLabel": null,
   "scopeLabel": "HTTP response contracts only. Backend access and action effects are not independently verified.",
   "durationMs": 104,
   "checksTotal": 9,
   "counts": {
    "pass": 9,
    "fail": 0,
    "inconclusive": 0,
    "error": 0,
    "not_applicable": 0
   },
   "results": [
    {
     "id": "ANA-ME",
     "title": "ANA-ME",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.equals predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type string; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.equals",
        "present": true,
        "type": "string",
        "outcome": "pass"
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "141809c9-6e17-4299-b74e-ea123024a164",
        "actorId": "ana",
        "method": "GET",
        "requestPathHash": "9d0546e5bc40f03f2839ab91824bb64ab8df2b72c8a66a9841bbd02a1dfa5975",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "a391a915434f70b86b7992e24931471bf39bfd30b1d49db7ec11a0a7a89ac7a5",
          "keys": [
           "18c2bf7d59cd2904ae6e20156dcaf30184f7e40b304ddda21acd580982faa062"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "aacd6f3b35ba3fe0523a362c051619fe352a44470c9d2357dc6c543c731a84db",
         "bodyKeys": "eb1c7dca6f514f065543fe3cb9664b03580504aa95f1fafcc703a75559d59db9" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 28,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-ME"
      ]
     },
     "durationMs": 12,
     "evidenceDigest": "a182582ccc16b9fa96dfe75ec7fd090f48bd04bf9a8aeb1736e4937d0fcf0147",
     "decision": "pass"
    },
    {
     "id": "GIL-ME",
     "title": "GIL-ME",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.equals predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type string; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.equals",
        "present": true,
        "type": "string",
        "outcome": "pass"
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "0814c2ac-7ea7-466d-ad0b-853db27c5b53",
        "actorId": "gil",
        "method": "GET",
        "requestPathHash": "9d0546e5bc40f03f2839ab91824bb64ab8df2b72c8a66a9841bbd02a1dfa5975",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "a391a915434f70b86b7992e24931471bf39bfd30b1d49db7ec11a0a7a89ac7a5",
          "keys": [
           "18c2bf7d59cd2904ae6e20156dcaf30184f7e40b304ddda21acd580982faa062"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "aacd6f3b35ba3fe0523a362c051619fe352a44470c9d2357dc6c543c731a84db",
         "bodyKeys": "eb1c7dca6f514f065543fe3cb9664b03580504aa95f1fafcc703a75559d59db9" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 30,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check GIL-ME"
      ]
     },
     "durationMs": 2,
     "evidenceDigest": "66912af532e62f60e084a97ebd798bc1691c5e446599aa589041fcbe99bf4833",
     "decision": "pass"
    },
    {
     "id": "ANA-OWN",
     "title": "ANA-OWN",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "b04a3eb7-5f27-4b15-bb19-5e1a8127a590",
        "actorId": "ana",
        "method": "GET",
        "requestPathHash": "d97183b60fbe5cf9c3ee18efe21d93544553407fcce668d470bc66b99804255d",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "096b6efc19f03d0a391bb6c45de95a406d55c0836fba2fb8062ab24553b2d0af",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f",
           "5944392a84c31435feb79de9263c9574fb34c0eb6f93b303c9d9884c381b7ae2",
           "5f1a1c2e4eada80ff7ab18a5b2f0e442eb089a08a878bca162ee815fea1391aa",
           "e97bc2a6bef444f1df95d919ae8344da7c3f98ba6f7325a95db3ea126ff95d0b"
          ]
         },
         {
          "exact": "41757e551cf2d2e41a4536a8873f452fbb84de51e97ded4f1b1f5312b0b50a6d",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "caa591fd8bcde217a8f1c6ed0c8dee6b7f689afdebb817df167c1f0891882eac",
         "bodyKeys": "256b97a2fe8ca854b73cceae800f4adbb4b32c663395500efdf8a3fa473b3193" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 43,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-OWN"
      ]
     },
     "durationMs": 5,
     "evidenceDigest": "9a0c9bf92e115f6199f47ed9508dcacfa81c7bac46a4732f38f184cc9a24c050",
     "decision": "pass"
    },
    {
     "id": "GIL-OWN",
     "title": "GIL-OWN",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "05f97b0a-2144-466d-afd9-527486d2882d",
        "actorId": "gil",
        "method": "GET",
        "requestPathHash": "3d20cda370d70f1103ee8e7ef5851072db65cdabd07b6396a51c534b0d5c8f01",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "096b6efc19f03d0a391bb6c45de95a406d55c0836fba2fb8062ab24553b2d0af",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f",
           "5944392a84c31435feb79de9263c9574fb34c0eb6f93b303c9d9884c381b7ae2",
           "5f1a1c2e4eada80ff7ab18a5b2f0e442eb089a08a878bca162ee815fea1391aa",
           "e97bc2a6bef444f1df95d919ae8344da7c3f98ba6f7325a95db3ea126ff95d0b"
          ]
         },
         {
          "exact": "58f5776d3becdde8123563a9f6a59a15d424e609281f68662c5c011c062a72ed",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "8a83b0c5fb90d058c4b5a4282e5a256111397fa0ca672c5f8df182bed8c03a63",
         "bodyKeys": "256b97a2fe8ca854b73cceae800f4adbb4b32c663395500efdf8a3fa473b3193" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 39,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check GIL-OWN"
      ]
     },
     "durationMs": 2,
     "evidenceDigest": "0e35fe791fe04c9a60b3ec5e060476e980fe6bf9e27840e30ab602dcc099e6c3",
     "decision": "pass"
    },
    {
     "id": "GIL-ASK",
     "title": "GIL-ASK",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "1ec6ef24-aaf6-472f-892c-070bfa4871d5",
        "actorId": "gil",
        "method": "POST",
        "requestPathHash": "5d4b1ce1ab6fc39a8ced60a839a7d62a4b342f4dee7895d74f67f3963aa84467",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "ce9a2c509b7177dbffc3a2f776727fa83ce954e4c4b43c7fab6b9406e848dc82",
          "keys": [
           "77ab5a7a2af9f12864acda031a6af3666fbdcd4c6077244a687ce9d3de7e4856",
           "b1d4ece910e38c5fe5a868c8e8697bd6da45d9ccc6e95f4ba0b1f7b992ee0908",
           "e6c9685e7e5a9d8f9cf836b2259246afac681ff372fa0285b3b57d228a29da89"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "f3a28b7e5bc8579b6f5477d79997f3d32e0a856a926adc5903cc2b630832fac3",
         "bodyKeys": "408b21b9fa5fe0f2ff88d4c0585a4be165fe24e4a818aa088b4d75897bbe5925" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 61,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check GIL-ASK"
      ]
     },
     "durationMs": 3,
     "evidenceDigest": "4c7addc2d125c3581d245ef5ad7597ca65c28bdaee6ea0ddc45aee08b7c9b6d4",
     "decision": "pass"
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER",
     "title": "ANA-NO-GLOBEX-ORDER",
     "category": "Tenant",
     "severity": "high",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 403 or 404",
       "actual": "HTTP 404"
      },
      {
       "name": "json.noForeignValues predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type object; other-tenant identifiers 0; other-tenant attributes 0; echoed identifiers 0; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 404,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.noForeignValues",
        "present": true,
        "type": "object",
        "outcome": "pass",
        "scan": "complete",
        "counts": {
         "identifiers": 0,
         "attributes": 0,
         "echoed": 0,
         "shared": 0,
         "overlapping": 0,
         "imprecise": 0,
         "partial": 0,
         "unplain": 0,
         "repeatedKeys": 0
        },
        "refs": []
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "8bc589a3-9a3a-4ba2-a7bd-6bb701140c9e",
        "actorId": "ana",
        "method": "GET",
        "requestPathHash": "3d20cda370d70f1103ee8e7ef5851072db65cdabd07b6396a51c534b0d5c8f01",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "096b6efc19f03d0a391bb6c45de95a406d55c0836fba2fb8062ab24553b2d0af",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f",
           "5944392a84c31435feb79de9263c9574fb34c0eb6f93b303c9d9884c381b7ae2",
           "5f1a1c2e4eada80ff7ab18a5b2f0e442eb089a08a878bca162ee815fea1391aa",
           "e97bc2a6bef444f1df95d919ae8344da7c3f98ba6f7325a95db3ea126ff95d0b"
          ]
         },
         {
          "exact": "58f5776d3becdde8123563a9f6a59a15d424e609281f68662c5c011c062a72ed",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "8a83b0c5fb90d058c4b5a4282e5a256111397fa0ca672c5f8df182bed8c03a63",
         "bodyKeys": null
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 404,
        "responseComplete": true,
        "responseBytes": 21,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-NO-GLOBEX-ORDER"
      ]
     },
     "durationMs": 24,
     "evidenceDigest": "4e569142d42c5aea2046b795b94d1f7f565b1c400992371502cb522f2d6cd180",
     "decision": "pass"
    },
    {
     "id": "ANA-CHAT",
     "title": "ANA-CHAT",
     "category": "Tenant",
     "severity": "high",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.noForeignValues predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type string; other-tenant identifiers 0; other-tenant attributes 0; echoed identifiers 0; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.noForeignValues",
        "present": true,
        "type": "string",
        "outcome": "pass",
        "scan": "complete",
        "counts": {
         "identifiers": 0,
         "attributes": 0,
         "echoed": 0,
         "shared": 0,
         "overlapping": 0,
         "imprecise": 0,
         "partial": 0,
         "unplain": 0,
         "repeatedKeys": 0
        },
        "refs": []
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "dcb066a5-7c75-45b8-a29c-839aa21a8629",
        "actorId": "ana",
        "method": "POST",
        "requestPathHash": "5d4b1ce1ab6fc39a8ced60a839a7d62a4b342f4dee7895d74f67f3963aa84467",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "ce9a2c509b7177dbffc3a2f776727fa83ce954e4c4b43c7fab6b9406e848dc82",
          "keys": [
           "77ab5a7a2af9f12864acda031a6af3666fbdcd4c6077244a687ce9d3de7e4856",
           "b1d4ece910e38c5fe5a868c8e8697bd6da45d9ccc6e95f4ba0b1f7b992ee0908",
           "e6c9685e7e5a9d8f9cf836b2259246afac681ff372fa0285b3b57d228a29da89"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "f3a28b7e5bc8579b6f5477d79997f3d32e0a856a926adc5903cc2b630832fac3",
         "bodyKeys": "408b21b9fa5fe0f2ff88d4c0585a4be165fe24e4a818aa088b4d75897bbe5925" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 59,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-CHAT"
      ]
     },
     "durationMs": 1,
     "evidenceDigest": "f475bc95bad1ecb102bb652cc6fcff487246812a5dc94906ab640dd37c3d67a8",
     "decision": "pass"
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER-mirror",
     "title": "ANA-NO-GLOBEX-ORDER (mirror under gil)",
     "category": "Tenant",
     "severity": "high",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 403 or 404",
       "actual": "HTTP 404"
      },
      {
       "name": "json.noForeignValues predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type object; other-tenant identifiers 0; other-tenant attributes 0; echoed identifiers 0; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 404,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.noForeignValues",
        "present": true,
        "type": "object",
        "outcome": "pass",
        "scan": "complete",
        "counts": {
         "identifiers": 0,
         "attributes": 0,
         "echoed": 0,
         "shared": 0,
         "overlapping": 0,
         "imprecise": 0,
         "partial": 0,
         "unplain": 0,
         "repeatedKeys": 0
        },
        "refs": []
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "f891e90a-4fff-419e-89da-7a84a6770b1a",
        "actorId": "gil",
        "method": "GET",
        "requestPathHash": "d97183b60fbe5cf9c3ee18efe21d93544553407fcce668d470bc66b99804255d",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "096b6efc19f03d0a391bb6c45de95a406d55c0836fba2fb8062ab24553b2d0af",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f",
           "5944392a84c31435feb79de9263c9574fb34c0eb6f93b303c9d9884c381b7ae2",
           "5f1a1c2e4eada80ff7ab18a5b2f0e442eb089a08a878bca162ee815fea1391aa",
           "e97bc2a6bef444f1df95d919ae8344da7c3f98ba6f7325a95db3ea126ff95d0b"
          ]
         },
         {
          "exact": "41757e551cf2d2e41a4536a8873f452fbb84de51e97ded4f1b1f5312b0b50a6d",
          "keys": [
           "3c1b4cf0b747390ac7a3b2c4f27d6db99a434735ab3acdf469870a5dc532119f"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "caa591fd8bcde217a8f1c6ed0c8dee6b7f689afdebb817df167c1f0891882eac",
         "bodyKeys": null
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 404,
        "responseComplete": true,
        "responseBytes": 21,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-NO-GLOBEX-ORDER-mirror"
      ]
     },
     "durationMs": 2,
     "evidenceDigest": "c8160c5c71cb1714857ee85c54033d279cf7deba6a0b40d40e42f41bdaaf5dc6",
     "decision": "pass"
    },
    {
     "id": "ANA-CHAT-mirror",
     "title": "ANA-CHAT (mirror under gil)",
     "category": "Tenant",
     "severity": "high",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.noForeignValues predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type string; other-tenant identifiers 0; other-tenant attributes 0; echoed identifiers 0; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.noForeignValues",
        "present": true,
        "type": "string",
        "outcome": "pass",
        "scan": "complete",
        "counts": {
         "identifiers": 0,
         "attributes": 0,
         "echoed": 0,
         "shared": 0,
         "overlapping": 0,
         "imprecise": 0,
         "partial": 0,
         "unplain": 0,
         "repeatedKeys": 0
        },
        "refs": []
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "eda22736-4e38-4ebe-a166-9b051e3ca635",
        "actorId": "gil",
        "method": "POST",
        "requestPathHash": "5d4b1ce1ab6fc39a8ced60a839a7d62a4b342f4dee7895d74f67f3963aa84467",
        "routeSegments": [
         {
          "exact": "5ad199ddbc64681042f23bce4acd134dfeb319a2f41f1f5ba9a593afaa9ea769",
          "keys": []
         },
         {
          "exact": "ce9a2c509b7177dbffc3a2f776727fa83ce954e4c4b43c7fab6b9406e848dc82",
          "keys": [
           "77ab5a7a2af9f12864acda031a6af3666fbdcd4c6077244a687ce9d3de7e4856",
           "b1d4ece910e38c5fe5a868c8e8697bd6da45d9ccc6e95f4ba0b1f7b992ee0908",
           "e6c9685e7e5a9d8f9cf836b2259246afac681ff372fa0285b3b57d228a29da89"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "f3a28b7e5bc8579b6f5477d79997f3d32e0a856a926adc5903cc2b630832fac3",
         "bodyKeys": "408b21b9fa5fe0f2ff88d4c0585a4be165fe24e4a818aa088b4d75897bbe5925" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 61,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-CHAT-mirror"
      ]
     },
     "durationMs": 2,
     "evidenceDigest": "55d2b5b8f4159a5fb3e793623385e8fde04167232e6f5129edb316ce7a938999",
     "decision": "pass"
    }
   ],
   "identityEvidence": {
    "schema": "actor-identity/6",
    "actors": [
     {
      "actorId": "ana",
      "credentialMode": "bearer",
      "requiredControlIds": [
       "ANA-ME",
       "ANA-OWN"
      ],
      "identityControlIds": [
       "ANA-ME"
      ],
      "surfaceControlIds": [
       "ANA-OWN"
      ],
      "refusesWith401": false,
      "refusalStatuses": [
       401,
       403
      ],
      "before": [
       {
        "controlId": "ANA-ME",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "ANA-OWN",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "between": [
       {
        "afterCheckId": "ANA-OWN",
        "probes": [
         {
          "controlId": "ANA-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "ANA-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       },
       {
        "afterCheckId": "ANA-NO-GLOBEX-ORDER",
        "probes": [
         {
          "controlId": "ANA-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "ANA-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       }
      ],
      "after": [
       {
        "controlId": "ANA-ME",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "ANA-OWN",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "anonymous": [
       {
        "controlId": "ANA-ME",
        "kind": "anonymous",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "invalid": [
       {
        "controlId": "ANA-ME",
        "kind": "invalid",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "cross": [
       {
        "controlId": "ANA-ME",
        "kind": "cross",
        "crossActorId": "gil",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "reason": "established",
      "loginProven": true,
      "established": true
     },
     {
      "actorId": "gil",
      "credentialMode": "bearer",
      "requiredControlIds": [
       "GIL-ME",
       "GIL-OWN"
      ],
      "identityControlIds": [
       "GIL-ME"
      ],
      "surfaceControlIds": [
       "GIL-OWN"
      ],
      "refusesWith401": false,
      "refusalStatuses": [
       401,
       403
      ],
      "before": [
       {
        "controlId": "GIL-ME",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "GIL-OWN",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "between": [
       {
        "afterCheckId": "GIL-OWN",
        "probes": [
         {
          "controlId": "GIL-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "GIL-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       },
       {
        "afterCheckId": "GIL-ASK",
        "probes": [
         {
          "controlId": "GIL-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "GIL-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       },
       {
        "afterCheckId": "ANA-NO-GLOBEX-ORDER-mirror",
        "probes": [
         {
          "controlId": "GIL-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "GIL-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       }
      ],
      "after": [
       {
        "controlId": "GIL-ME",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "GIL-OWN",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "anonymous": [
       {
        "controlId": "GIL-ME",
        "kind": "anonymous",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "invalid": [
       {
        "controlId": "GIL-ME",
        "kind": "invalid",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "cross": [
       {
        "controlId": "GIL-ME",
        "kind": "cross",
        "crossActorId": "ana",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "reason": "established",
      "loginProven": true,
      "established": true
     }
    ]
   },
   "principals": {
    "ana": "ana-1",
    "gil": "gil-1",
    "anonymous": "anonymous"
   },
   "tenantValueCounts": {
    "attributesAlone": "inconclusive",
    "tenants": [
     {
      "identifiers": 2,
      "attributes": 1
     },
     {
      "identifiers": 2,
      "attributes": 0
     },
     {
      "identifiers": 1,
      "attributes": 0
     }
    ],
    "actorTenants": {
     "ana": 1,
     "gil": 2
    }
   },
   "limitations": [
    "The connector assessed an operator-configured local application using HTTP response predicates; it did not independently observe backend retrieval or tool effects.",
    "Application, actor, build and data-context identities are declared by the profile. The target may have its own model, database or network dependencies.",
    "A passing response contract is not a security certification. Requirements needing backend evidence remain inconclusive when response predicates pass.",
    "Raw request/response content and credentials are not retained. Reproducing a predicate requires the original private profile and comparable target state.",
    "Requests run once without retries or automatic reset. A timed-out POST, PUT, PATCH or DELETE may still have executed; inspect the target before retrying manually.",
    "Other-tenant values (json.noForeignValues): The value at the pointer is read as leaves (every string, every object key, and every JSON number as the response body writes it) under an allowlist rule. It fails only on another tenant's identifier written literally (its exact declared characters, spaces at its ends trimmed) as a whole token, in an occurrence that no value of another set of owner tenants overlaps, that the check's own request does not carry. It passes only when every leaf is in the plain form, the response body repeats no member name, and no other tenant's value occurs in any reading, except that under \"attributesAlone\": \"ignore\" an attribute seen as a whole token does not prevent a pass. Everything else reads inconclusive, never pass. A response body with a repeated member name in any object reads inconclusive, never pass, because JSON parsing keeps only the last of the repeated values (the connector counts repeats on the raw body); another tenant's identifier written literally in the parsed value still fails. The connector also keeps each JSON number's source text, so 7.50, 731e-400 and 12345678901234567 are read with the digits the body shows; a transport that reports neither, and a body nested too deeply for the connector's second parse, read inconclusive unless another tenant's identifier is written literally as a whole token, which still fails. The plain form: ASCII letters and digits, the other letters and decimal digits that occur in some declared value (only those that Unicode assigns to one of these scripts: Latin, Greek, Cyrillic, Armenian, Georgian, Cherokee, Hebrew, Arabic, Syriac, Thaana, NKo, Han with kana and Bopomofo, Hangul, Thai, Lao, Khmer, Myanmar, Devanagari, Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam, Sinhala and Ethiopic; never Common, Inherited or default-ignorable ones; and in a script with letter case only letters that have an uppercase or lowercase partner), U+0020 spaces, U+000A line feeds and the punctuation . , ; : ! ? ' \" ( ) - / @ # $, in a leaf that Unicode NFKC normalization leaves unchanged and that does not hold ASCII digits beside other decimal digits. An object member name that is an array index (0 to 4294967294, written without leading zeros) is outside the form when the object has another member, since JavaScript lists such names first and the body's order of the members is not known. Across the whole value at the pointer, every letter and every number character other than an ASCII digit, in every leaf and in every other tenant's declared values, must be of one script group (Han, kana and Bopomofo count as one; a script not listed counts as a group of its own); otherwise every leaf holding such a character is outside the form, since a reply in one script can show another script's value in look-alike letters. Likewise, when right-to-left letters or digits occur anywhere at the pointer together with left-to-right letters or digits (ASCII digits are left-to-right), or the response body holds anywhere a character of the right-to-left blocks (U+0590 to U+08FF, U+FB1D to U+FDFF, U+FE70 to U+FEFF, U+10800 to U+10FFF, U+1E800 to U+1EFFF) or a bidi control, every leaf at the pointer holding a letter or digit of either direction is outside the form, since the display order of one leaf depends on the text around it. Any escape (a backslash, a percent sign, an HTML entity), any markup character (< > * _ ~ `), any control, format, bidi, default-ignorable or combining character, a compatibility form such as fullwidth letters, any letter or digit no declared value uses (small capitals, IPA letters, spacing modifier letters, letters drawn like punctuation, the katakana long vowel mark, the Arabic tatweel), letters or numbers of two script groups (in the reply, or the reply's and another tenant's values), a tab, a carriage return and any other symbol puts its leaf outside the form, and such a leaf reads inconclusive unless another tenant's identifier is written literally in it (accepted recall loss: replies with curly quotes, markdown, emoji, accents written as combining marks, Indic and Thai text, any accented or non-Latin letter that no declared value uses, katakana words with the long vowel mark, a leaf that mixes scripts, such as a Cyrillic name in an English sentence, and every reply with a letter when other tenants' values use another script group or more than one, such as a Latin reply when another tenant holds a Cyrillic name, read inconclusive). The loose reading keeps only letters and number characters, each after Unicode NFKD decomposition with every combining mark removed, before and after a full case fold (the capital and the small sharp s both read ss), with ligatures and letters with a stroke or bar read as their base letters from a fixed list in src/tenant-values.mjs (æ ae, œ oe, þ th, ø o, ł l, đ d, ħ h, ƶ z, ғ г and others), Hebrew final letters as their base letters, the Persian yeh and keheh, the alef maksura and the teh marbuta as yeh, kaf, yeh and heh, katakana as hiragana, an iteration mark (々, ゝ) as the letter right before it (one with no letter right before it in its leaf reads as nothing and puts the leaf outside the form), the ideographic zero as 0 and every decimal digit as its ASCII digit; a declared value with ä, ö, ü, å or ø is also read with those letters spelled ae, oe, ue, aa and oe, and one with ae, oe, ue or aa also with those written a, o, u and a; a value seen there anywhere but inside its own whole literal occurrence (in another letter case, with its accents removed, with other spacing, punctuation or line breaks between its characters, or glued to more letters or digits) reads inconclusive, never fail. The joined readings are the loose reading with the leaf boundaries removed, in order (array items in order, each object key before its value, object members in JavaScript property order), once over every leaf and once over the leaves that are not object keys; a value seen there across a leaf boundary ([\"REF-\", \"5150\"], {\"REF\": 5150}, {\"first\": \"Grace\", \"last\": \"Hopper\"}) reads inconclusive, never pass. The number readings are the loose reading and the joined readings with the zeros at both ends of every run of ASCII digits removed (a run of zeros vanishes); a value with a digit, read the same way, seen there reads inconclusive, never pass, unless an end of it that is a digit meets, past any zeros written right beside it, another digit written right beside it, so 17310 and 7.51 are other numbers than 731 and 7.5 (\"Order 731\", \"Order 731 2 items\" or \"Order 7.31e2\" for \"00731\", \"7.5\" for \"7.50\", \"INV-42\" for \"INV-0042\", \"1,000\" for \"1000.00\"; accepted recall loss: 7310 reads like 731, 1, 10, 0.1 and 100.00 read alike, and \"ABC\" reads like \"ABC-000\"; a value made of zeros only, such as \"0.00\", has no number reading). A token edge is open at a leaf edge, beside a space or line feed, or beside a run of the listed punctuation that ends at a leaf edge, space or line feed. No edge closes: any other neighbor is glue and reads inconclusive (a letter or digit of any case, a character outside the form, or punctuation that meets a letter or digit: \"orderREF-5150\", \"REF-51501\", \"REF-5150-B\", \"/orders/REF-5150\", \"myjdoe42\" for \"jdoe42\"; accepted recall loss: a longer word that holds a value, such as \"Hoppers\", \"Anne\", \"annual\" or \"Joanna\" for \"Hopper\" and \"Ann\", reads inconclusive too). A value whose first or last character is not a letter or digit (\"@example.net\") has an open edge there unless its neighbor is a character other than a letter, digit, space, line feed or listed punctuation. Also inconclusive: a value the actor's tenant shares with another tenant, an identifier two or more other tenants share (an attribute that only other tenants share counts as an attribute), a value seen only in occurrences that overlap an occurrence of a value with another set of owner tenants (the actor's own \"Grace Hopper\" holding another tenant's \"Hopper\", or another tenant's \"5150\" glued inside the actor's \"REF-5150\"), another tenant's identifier whose loose reading occurs in the request's decoded path, query, body keys, strings or numbers (an echo: \"I can't share REF-5150\" and a reply that returns that record cannot be told apart), a leaf that is a number (a JSON number, or a string of decimal text alone) equal to a declared decimal value written differently, leading zeros included (\"7.50\" for 7.5, \"02134\" for 2134, the string \"7.5\" for \"7.50\"). Declared values with the same loose reading are one value, and it is an identifier when any tenant declares it as one, so the result does not depend on declaration order. A declared value that Unicode NFKC normalization changes (decomposed accents, compatibility forms) is refused. Not seen: a value the profile did not declare, a paraphrase, a value spelled out or written in another spelling than these readings give (\"Mohammed\" for \"Muhammad\"), a value split across leaves in another order or with another leaf between its parts ({\"num\": 5150, \"prefix\": \"REF-\"}), a number rounded to other digits (\"7.49\" for \"7.5\"), a value written in look-alike letters of its own script group, a value with a letter replaced by another letter of the plain form (an accented letter some declared value uses, or an ASCII look-alike such as \"O\" for \"0\"), a number a renderer computes, such as the item numbers of a Markdown ordered list, and a display that sets a right-to-left direction itself. Attributes seen as whole tokens on their own read inconclusive by default, or are ignored under \"attributesAlone\": \"ignore\"; an attribute seen only partially, or only as a number written differently, reads inconclusive under either policy. The scan reads at most 131072 characters (524288 in its loose reading) and judges at most 262144 matches; past either bound it reads inconclusive. Saved evidence names a matched value only by its position in the profile (tenant n, identifier m), never by the value.",
    "A credentialed actor's login counts only with positive evidence in the same run: a required GET control returning its declared identity, refused without a credential, with an invalid credential (a random look-alike of the actor's own, made fresh each run) and with each other actor's credential, and passing again with the actor's surface controls (its other required GET controls, on protected routes) at a probe point before the actor's first other check and after each of them, each probe in full. Identity is judged per check (actor-identity/5): a check rests on that identity route proof and on the two probe points around it. A point that did not pass withholds the checks it covers, ranked across both of a check's points, except that a required control is withheld only for a login-level reason (an identity probe that did not pass or did not finish at a point covering it, or a probe refused at any point), never because a surface probe failed for another reason; a check whose own two points passed keeps its status when another point fails. A probe refused with the actor's own credential at any point withholds every check of the actor, required and identity controls included, since a credential that flaps can be refused between two accepting points: a refused identity probe (401, 403, its declared sign-in redirect, or a complete 2xx that names another principal or none) reads bracket-not-passed, a refused surface probe (401, 403 or the declared redirect: the protected routes did not accept the credential the identity route accepted) reads surface-refused, and bracket-not-passed when both were refused. A surface probe that fails otherwise (a 500, a 404) leaves the checks its point covers not established. A withheld check is inconclusive; a boundary check whose refusal was observed while its identity or allowed use was not established is the distinct decision prohibition-observed-identity-unproven, never a pass. The gate reports identity-not-established for an actor whose route or any point did not hold, and a comparison never labels a row restored or fixed when its identity was not proven for it. A credentialed 401 on a boundary check is an authentication failure, not a refusal, unless the actor declares refusesWith401 and a surface control brackets its checks. A 403 or any other answer outside 2xx counts as a refusal only after the same actor's complete 2xx on a protected route (a surface control in its probe points); without one it is inconclusive. An outage strictly between the two probe points that cover a check is not detected. Evidence of credential loss on an actor's own main rows, rather than at a probe point, stays row-level: a credentialed 401 on a boundary check (unauthenticated-401), a redirect to the declared sign-in, or a required control answering a refusal status withholds or fails that row, and the gate fails, but a comparison may still credit other rows of that actor, and a change or a captured value that actor made still counts as attributed."
   ]
  }
 },
 "undeclared": {
  "profile": {
   "id": "two-desk",
   "name": "Two-tenant desk (test)",
   "applicationId": "two-desk",
   "origin": "http://127.0.0.1:50051",
   "buildLabel": "fixed",
   "contextId": "synthetic-two",
   "actors": {
    "ana": {
     "principalId": "ana-1",
     "tenantId": "acme",
     "role": "member",
     "credentialEnv": "SCOPEHAVEN_TARGET_ANA",
     "identityValue": "ana@acme.example"
    },
    "gil": {
     "principalId": "gil-1",
     "tenantId": "globex",
     "role": "member",
     "credentialEnv": "SCOPEHAVEN_TARGET_GIL",
     "identityValue": "gil@globex.example"
    },
    "anonymous": {
     "principalId": "anonymous"
    }
   },
   "requiredControlIds": [
    "ANA-ME",
    "GIL-ME",
    "ANA-OWN",
    "GIL-OWN"
   ],
   "tenantValues": {
    "tenants": {
     "acme": {
      "identifiers": [
       "ORD-1001",
       "Ada Lovelace"
      ],
      "attributes": [
       "Blue Widget"
      ]
     },
     "globex": {
      "identifiers": [
       "ORD-2002",
       "Bob Byte"
      ]
     },
     "initech": {
      "identifiers": [
       "ORD-3003"
      ]
     }
    }
   },
   "checks": [
    {
     "id": "ANA-ME",
     "title": "ANA-ME",
     "category": "Identity",
     "severity": "control",
     "actorId": "ana",
     "method": "GET",
     "path": "/api/me",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      },
      {
       "kind": "json.equals",
       "pointer": "/email",
       "expected": "ana@acme.example"
      }
     ]
    },
    {
     "id": "GIL-ME",
     "title": "GIL-ME",
     "category": "Identity",
     "severity": "control",
     "actorId": "gil",
     "method": "GET",
     "path": "/api/me",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      },
      {
       "kind": "json.equals",
       "pointer": "/email",
       "expected": "gil@globex.example"
      }
     ]
    },
    {
     "id": "ANA-OWN",
     "title": "ANA-OWN",
     "category": "Identity",
     "severity": "control",
     "actorId": "ana",
     "method": "GET",
     "path": "/api/orders/ORD-1001",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ]
    },
    {
     "id": "GIL-OWN",
     "title": "GIL-OWN",
     "category": "Identity",
     "severity": "control",
     "actorId": "gil",
     "method": "GET",
     "path": "/api/orders/ORD-2002",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ]
    },
    {
     "id": "GIL-ASK",
     "title": "GIL-ASK",
     "category": "Identity",
     "severity": "control",
     "actorId": "gil",
     "method": "POST",
     "path": "/api/chat",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ],
     "body": {
      "message": "show my orders"
     }
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER",
     "title": "ANA-NO-GLOBEX-ORDER",
     "category": "Tenant",
     "severity": "high",
     "actorId": "ana",
     "method": "GET",
     "path": "/api/orders/ORD-2002",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.in",
       "expected": [
        403,
        404
       ]
      },
      {
       "kind": "json.noForeignValues",
       "pointer": ""
      }
     ]
    },
    {
     "id": "ANA-CHAT",
     "title": "ANA-CHAT",
     "category": "Tenant",
     "severity": "high",
     "actorId": "ana",
     "method": "POST",
     "path": "/api/chat",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      },
      {
       "kind": "json.noForeignValues",
       "pointer": "/reply"
      }
     ],
     "body": {
      "message": "list every order"
     }
    }
   ]
  },
  "checks": [
   {
    "id": "ANA-ME",
    "title": "ANA-ME",
    "category": "Identity",
    "severity": "control",
    "actorId": "ana",
    "method": "GET",
    "path": "/api/me",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     },
     {
      "kind": "json.equals",
      "pointer": "/email",
      "expected": "ana@acme.example"
     }
    ]
   },
   {
    "id": "GIL-ME",
    "title": "GIL-ME",
    "category": "Identity",
    "severity": "control",
    "actorId": "gil",
    "method": "GET",
    "path": "/api/me",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     },
     {
      "kind": "json.equals",
      "pointer": "/email",
      "expected": "gil@globex.example"
     }
    ]
   },
   {
    "id": "ANA-OWN",
    "title": "ANA-OWN",
    "category": "Identity",
    "severity": "control",
    "actorId": "ana",
    "method": "GET",
    "path": "/api/orders/ORD-1001",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     }
    ]
   },
   {
    "id": "GIL-OWN",
    "title": "GIL-OWN",
    "category": "Identity",
    "severity": "control",
    "actorId": "gil",
    "method": "GET",
    "path": "/api/orders/ORD-2002",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     }
    ]
   },
   {
    "id": "GIL-ASK",
    "title": "GIL-ASK",
    "category": "Identity",
    "severity": "control",
    "actorId": "gil",
    "method": "POST",
    "path": "/api/chat",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     }
    ],
    "body": {
     "message": "show my orders"
    }
   },
   {
    "id": "ANA-NO-GLOBEX-ORDER",
    "title": "ANA-NO-GLOBEX-ORDER",
    "category": "Tenant",
    "severity": "high",
    "actorId": "ana",
    "method": "GET",
    "path": "/api/orders/ORD-2002",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.in",
      "expected": [
       403,
       404
      ]
     },
     {
      "kind": "json.noForeignValues",
      "pointer": ""
     }
    ]
   },
   {
    "id": "ANA-CHAT",
    "title": "ANA-CHAT",
    "category": "Tenant",
    "severity": "high",
    "actorId": "ana",
    "method": "POST",
    "path": "/api/chat",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     },
     {
      "kind": "json.noForeignValues",
      "pointer": "/reply"
     }
    ],
    "body": {
     "message": "list every order"
    }
   }
  ],
  "contractDigest": "aae2fbf039fb7fc156f57cb2784195ca46cb9c269fce048babc02955bf4f7801",
  "suite": {
   "id": "two-desk-contracts",
   "targetId": "two-desk",
   "applicationId": "two-desk",
   "version": "http-contract/4",
   "evidenceOrigin": "local-http-response",
   "hash": "aae2fbf039fb7fc156f57cb2784195ca46cb9c269fce048babc02955bf4f7801",
   "scope": "Definition summary only; private request bodies, expected values, actor credentials and endpoints are omitted.",
   "requiredControlIds": [
    "ANA-ME",
    "GIL-ME",
    "ANA-OWN",
    "GIL-OWN"
   ],
   "checks": [
    {
     "id": "ANA-ME",
     "title": "ANA-ME",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals",
      "json.equals"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "identityControl": true,
     "identityPredicate": 0,
     "refusalStatuses": [
      401,
      403
     ],
     "refusesWith401": false,
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "GIL-ME",
     "title": "GIL-ME",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals",
      "json.equals"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "identityControl": true,
     "identityPredicate": 0,
     "refusalStatuses": [
      401,
      403
     ],
     "refusesWith401": false,
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "ANA-OWN",
     "title": "ANA-OWN",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "GIL-OWN",
     "title": "GIL-OWN",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "GIL-ASK",
     "title": "GIL-ASK",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "gil",
     "credentialMode": "bearer",
     "recordPredicates": []
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER",
     "title": "ANA-NO-GLOBEX-ORDER",
     "category": "Tenant",
     "severity": "high",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.in",
      "json.noForeignValues"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "recordPredicates": []
    },
    {
     "id": "ANA-CHAT",
     "title": "ANA-CHAT",
     "category": "Tenant",
     "severity": "high",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals",
      "json.noForeignValues"
     ],
     "actorId": "ana",
     "credentialMode": "bearer",
     "recordPredicates": []
    }
   ],
   "identitySchema": "actor-identity/6",
   "principalsDigest": "679a690f10f1168edc31946216aaf97ced2e5043fb281306c2d5b174f3067b8d",
   "tenantValues": {
    "attributesAlone": "inconclusive",
    "tenants": [
     {
      "identifiers": 2,
      "attributes": 1
     },
     {
      "identifiers": 2,
      "attributes": 0
     },
     {
      "identifiers": 1,
      "attributes": 0
     }
    ],
    "actorTenants": {
     "ana": 1,
     "gil": 2
    }
   },
   "targetContext": "local-app",
   "targetLabel": null,
   "runnableWith": "Use the original local profile with ./scopehaven assess --config <file> --target <id>. This redacted summary is not an executable profile."
  },
  "seen": [
   "GET /api/me ana",
   "GET /api/me gil",
   "GET /api/me ana",
   "GET /api/orders/ORD-1001 ana",
   "GET /api/orders/ORD-1001 ana",
   "GET /api/me ana",
   "GET /api/orders/ORD-1001 ana",
   "GET /api/me gil",
   "GET /api/orders/ORD-2002 gil",
   "GET /api/orders/ORD-2002 gil",
   "GET /api/me gil",
   "GET /api/orders/ORD-2002 gil",
   "POST /api/chat gil",
   "GET /api/me gil",
   "GET /api/orders/ORD-2002 gil",
   "GET /api/orders/ORD-2002 ana",
   "GET /api/me ana",
   "GET /api/orders/ORD-1001 ana",
   "POST /api/chat ana",
   "GET /api/me ana",
   "GET /api/orders/ORD-1001 ana",
   "GET /api/me none",
   "GET /api/me invalid",
   "GET /api/me gil",
   "GET /api/me none",
   "GET /api/me invalid",
   "GET /api/me ana"
  ],
  "cli": {
   "--check-config": {
    "status": 0,
    "stderr": "",
    "target": {
     "id": "two-desk",
     "name": "Two-tenant desk (test)",
     "kind": "http-contract",
     "checks": 7,
     "available": true,
     "credentialsReady": true,
     "missingCredentialRefs": [],
     "twoIdentities": {
      "tenantScoped": true,
      "identities": [
       "ana",
       "gil"
      ],
      "distinctTenants": 2,
      "singleIdentity": false,
      "extraRequests": [],
      "mirrored": [],
      "notMirrored": [
       {
        "checkId": "ANA-NO-GLOBEX-ORDER",
        "reason": "mirrors-undeclared"
       },
       {
        "checkId": "ANA-CHAT",
        "reason": "mirrors-undeclared"
       }
      ]
     }
    }
   },
   "--list": {
    "status": 0,
    "stderr": "",
    "target": {
     "id": "two-desk",
     "name": "Two-tenant desk (test)",
     "kind": "http-contract",
     "checks": 7,
     "available": true,
     "credentialsReady": true,
     "missingCredentialRefs": [],
     "twoIdentities": {
      "tenantScoped": true,
      "identities": [
       "ana",
       "gil"
      ],
      "distinctTenants": 2,
      "singleIdentity": false,
      "extraRequests": [],
      "mirrored": [],
      "notMirrored": [
       {
        "checkId": "ANA-NO-GLOBEX-ORDER",
        "reason": "mirrors-undeclared"
       },
       {
        "checkId": "ANA-CHAT",
        "reason": "mirrors-undeclared"
       }
      ]
     }
    }
   }
  },
  "run": {
   "schemaVersion": 1,
   "id": "e6ef1951-26cc-4af6-81fb-cfe7d9a6ed3b",
   "createdAt": "2026-10-25T17:45:50.776Z",
   "targetId": "two-desk",
   "targetName": "Two-tenant desk (test)",
   "build": "fixed",
   "applicationId": "two-desk",
   "suiteId": "two-desk-contracts",
   "suiteHash": "0984aa6760bc6a336d57beb5ccbe5d7cb58427d4e42f0b9d71020ff8d7620d9e",
   "policyHash": "0984aa6760bc6a336d57beb5ccbe5d7cb58427d4e42f0b9d71020ff8d7620d9e",
   "profileHash": "aae2fbf039fb7fc156f57cb2784195ca46cb9c269fce048babc02955bf4f7801",
   "contextId": "synthetic-two",
   "fixtureVersion": "operator-declared-context/1",
   "fixtureHash": "c544fc290ce205372c95b5ead32a2df8f81bc36b5296096a475a276c5f576f81",
   "adapterVersion": "loopback-response-contract/3",
   "assertionSchemaVersion": "http-contract/4",
   "evaluatorHash": "f228ce9b23b2782b491bafb6b3b69fca88024ec5b6bd29c70dcae3335656b679",
   "requiredControlIds": [
    "ANA-ME",
    "GIL-ME",
    "ANA-OWN",
    "GIL-OWN"
   ],
   "evidenceOrigin": "local-http-response",
   "runtimeMode": "configured-local-application",
   "targetBuildHash": null,
   "targetConfigHash": "f9761580c707015c687b2cb07c30eaa47ac02b56d4804508cfe26855b7c984b7",
   "buildIdentity": "Declared in configuration; not independently attested.",
   "targetContext": "local-app",
   "targetLabel": null,
   "scopeLabel": "HTTP response contracts only. Backend access and action effects are not independently verified.",
   "durationMs": 32,
   "checksTotal": 7,
   "counts": {
    "pass": 7,
    "fail": 0,
    "inconclusive": 0,
    "error": 0,
    "not_applicable": 0
   },
   "results": [
    {
     "id": "ANA-ME",
     "title": "ANA-ME",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.equals predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type string; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.equals",
        "present": true,
        "type": "string",
        "outcome": "pass"
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "02a60dab-a47c-4905-9f8f-32be52f832fc",
        "actorId": "ana",
        "method": "GET",
        "requestPathHash": "9d0546e5bc40f03f2839ab91824bb64ab8df2b72c8a66a9841bbd02a1dfa5975",
        "routeSegments": [
         {
          "exact": "1fc2a6fa22bdcdacf295c687587eeb6732a73a2e2666621e4dcaf2f112d727a7",
          "keys": []
         },
         {
          "exact": "74840726256692198289207aadf13e9b3042b6bc17704e2fd98286372ebc2515",
          "keys": [
           "19f22b59433dddc5aaaa5e451e8f1d079aca41c874b3fd97ce547138b3af71cf"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "710cfea152fa2d5bbdd1417635097801b972d29a6b98015d63995b46ecfa3fbf",
         "bodyKeys": "e60e015f6172fbb99c505e0c0068b71d5e1df438563b81b93442b0258259818a" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 28,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-ME"
      ]
     },
     "durationMs": 2,
     "evidenceDigest": "72ad264dd4d1b7cd02505c0bafa0a2ed25f0447070b7a9fd79ed31758410abbb",
     "decision": "pass"
    },
    {
     "id": "GIL-ME",
     "title": "GIL-ME",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.equals predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type string; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.equals",
        "present": true,
        "type": "string",
        "outcome": "pass"
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "720de3f1-28a7-4ff3-bd67-57de77eb7522",
        "actorId": "gil",
        "method": "GET",
        "requestPathHash": "9d0546e5bc40f03f2839ab91824bb64ab8df2b72c8a66a9841bbd02a1dfa5975",
        "routeSegments": [
         {
          "exact": "1fc2a6fa22bdcdacf295c687587eeb6732a73a2e2666621e4dcaf2f112d727a7",
          "keys": []
         },
         {
          "exact": "74840726256692198289207aadf13e9b3042b6bc17704e2fd98286372ebc2515",
          "keys": [
           "19f22b59433dddc5aaaa5e451e8f1d079aca41c874b3fd97ce547138b3af71cf"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "710cfea152fa2d5bbdd1417635097801b972d29a6b98015d63995b46ecfa3fbf",
         "bodyKeys": "e60e015f6172fbb99c505e0c0068b71d5e1df438563b81b93442b0258259818a" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 30,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check GIL-ME"
      ]
     },
     "durationMs": 1,
     "evidenceDigest": "05d42ee5a3453421d89f08d77adf577d8470b16d06e32e4f58fb19a97fc94995",
     "decision": "pass"
    },
    {
     "id": "ANA-OWN",
     "title": "ANA-OWN",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "8d3c9aec-0ec5-4de4-bbd3-de40d25062d3",
        "actorId": "ana",
        "method": "GET",
        "requestPathHash": "d97183b60fbe5cf9c3ee18efe21d93544553407fcce668d470bc66b99804255d",
        "routeSegments": [
         {
          "exact": "1fc2a6fa22bdcdacf295c687587eeb6732a73a2e2666621e4dcaf2f112d727a7",
          "keys": []
         },
         {
          "exact": "bf29451cd5753bd1628df4b2a15bc53ccec44d62b578067d906bd01328d232cf",
          "keys": [
           "0e9a1e10deb563e1ca48b6f12ccab4b53117c963e8e458832a90fe5ffb1d2631",
           "3d992d258c1c736518377c278fa28775b84f072c82f587dc84bc1f67bc30a8cf",
           "48cfd5732249d6fb31b366b13c55b85ac41685336bea3cb1c9e3b5db696b2f40",
           "a14a5c8e1af6a75d2302cd11cd6725d4e09f6ac059b4072b602ba9252bd17892"
          ]
         },
         {
          "exact": "4a320696c4a98598b9fee9164dbcd340073d2700c3f0717e01393544f338117f",
          "keys": [
           "48cfd5732249d6fb31b366b13c55b85ac41685336bea3cb1c9e3b5db696b2f40"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "37a2777d963d76e75e40d762c8f03119814b16bce3f83e77952c7f30f55a8b7a",
         "bodyKeys": "6f61f5cd468558447b14b36aa97be80ec06e2a412c2529fb6d730492434d68a0" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 43,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-OWN"
      ]
     },
     "durationMs": 1,
     "evidenceDigest": "95553a9a7cca6f5d0826db32b9de488cbf3fda7b527cf9310892205b7dbdc262",
     "decision": "pass"
    },
    {
     "id": "GIL-OWN",
     "title": "GIL-OWN",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "09aa37a3-acba-4c33-9bbe-591680764da3",
        "actorId": "gil",
        "method": "GET",
        "requestPathHash": "3d20cda370d70f1103ee8e7ef5851072db65cdabd07b6396a51c534b0d5c8f01",
        "routeSegments": [
         {
          "exact": "1fc2a6fa22bdcdacf295c687587eeb6732a73a2e2666621e4dcaf2f112d727a7",
          "keys": []
         },
         {
          "exact": "bf29451cd5753bd1628df4b2a15bc53ccec44d62b578067d906bd01328d232cf",
          "keys": [
           "0e9a1e10deb563e1ca48b6f12ccab4b53117c963e8e458832a90fe5ffb1d2631",
           "3d992d258c1c736518377c278fa28775b84f072c82f587dc84bc1f67bc30a8cf",
           "48cfd5732249d6fb31b366b13c55b85ac41685336bea3cb1c9e3b5db696b2f40",
           "a14a5c8e1af6a75d2302cd11cd6725d4e09f6ac059b4072b602ba9252bd17892"
          ]
         },
         {
          "exact": "a6139f9c10126933df11b62f3d2f161f6c279aa4dc5649f5336607d726f123da",
          "keys": [
           "48cfd5732249d6fb31b366b13c55b85ac41685336bea3cb1c9e3b5db696b2f40"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "6f66e552f08965513d275ab763a026a26799b7759a7e3d4d643c2c91051ba896",
         "bodyKeys": "6f61f5cd468558447b14b36aa97be80ec06e2a412c2529fb6d730492434d68a0" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 39,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check GIL-OWN"
      ]
     },
     "durationMs": 1,
     "evidenceDigest": "1e004690baf49b205d9f413dd0d01e075e226aacc738c98bc7fee8883d586ebf",
     "decision": "pass"
    },
    {
     "id": "GIL-ASK",
     "title": "GIL-ASK",
     "category": "Identity",
     "severity": "control",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "bb067547-fdc7-4e46-b0e8-cce5ac017d5d",
        "actorId": "gil",
        "method": "POST",
        "requestPathHash": "5d4b1ce1ab6fc39a8ced60a839a7d62a4b342f4dee7895d74f67f3963aa84467",
        "routeSegments": [
         {
          "exact": "1fc2a6fa22bdcdacf295c687587eeb6732a73a2e2666621e4dcaf2f112d727a7",
          "keys": []
         },
         {
          "exact": "8e7c6b98c702313e28a7c52aacbebdc7a932cb83779d4249e5f12d15ca098283",
          "keys": [
           "2f8688d50f8fd8b1f232a3d00adfc8d79d0082b1c8f0c04f06f75adfc205f76c",
           "37070cfe6b022b84e1493f2d6b3fc633a4561bcc910c8d6b13ccbe66958c9f4d",
           "c7937119cfa8b3e5f14d6fa439c3a4bfd269dd6fd1aeb4fa159999af9cae3668"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "b16e1da5b1e17b511c37dc0d747aa48947417a172c66aae03ff61308a609757d",
         "bodyKeys": "535bca7636f67dbf5951f1d62d0aa37bc3408debc81d702fe985c9f71785bf03" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 61,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check GIL-ASK"
      ]
     },
     "durationMs": 1,
     "evidenceDigest": "d05bf9b6fef3eeeed69b05b680d97b33eccbdf94135ad3ae50b7773d396b7767",
     "decision": "pass"
    },
    {
     "id": "ANA-NO-GLOBEX-ORDER",
     "title": "ANA-NO-GLOBEX-ORDER",
     "category": "Tenant",
     "severity": "high",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 403 or 404",
       "actual": "HTTP 404"
      },
      {
       "name": "json.noForeignValues predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type object; other-tenant identifiers 0; other-tenant attributes 0; echoed identifiers 0; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 404,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.noForeignValues",
        "present": true,
        "type": "object",
        "outcome": "pass",
        "scan": "complete",
        "counts": {
         "identifiers": 0,
         "attributes": 0,
         "echoed": 0,
         "shared": 0,
         "overlapping": 0,
         "imprecise": 0,
         "partial": 0,
         "unplain": 0,
         "repeatedKeys": 0
        },
        "refs": []
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "d5daa10b-b348-4b18-ba9c-9dd823cd5a41",
        "actorId": "ana",
        "method": "GET",
        "requestPathHash": "3d20cda370d70f1103ee8e7ef5851072db65cdabd07b6396a51c534b0d5c8f01",
        "routeSegments": [
         {
          "exact": "1fc2a6fa22bdcdacf295c687587eeb6732a73a2e2666621e4dcaf2f112d727a7",
          "keys": []
         },
         {
          "exact": "bf29451cd5753bd1628df4b2a15bc53ccec44d62b578067d906bd01328d232cf",
          "keys": [
           "0e9a1e10deb563e1ca48b6f12ccab4b53117c963e8e458832a90fe5ffb1d2631",
           "3d992d258c1c736518377c278fa28775b84f072c82f587dc84bc1f67bc30a8cf",
           "48cfd5732249d6fb31b366b13c55b85ac41685336bea3cb1c9e3b5db696b2f40",
           "a14a5c8e1af6a75d2302cd11cd6725d4e09f6ac059b4072b602ba9252bd17892"
          ]
         },
         {
          "exact": "a6139f9c10126933df11b62f3d2f161f6c279aa4dc5649f5336607d726f123da",
          "keys": [
           "48cfd5732249d6fb31b366b13c55b85ac41685336bea3cb1c9e3b5db696b2f40"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "6f66e552f08965513d275ab763a026a26799b7759a7e3d4d643c2c91051ba896",
         "bodyKeys": null
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 404,
        "responseComplete": true,
        "responseBytes": 21,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-NO-GLOBEX-ORDER"
      ]
     },
     "durationMs": 1,
     "evidenceDigest": "4f9fe910aebd413f30524f0177bd231ea0423c2234501764a3cfaa3d50fa7f45",
     "decision": "pass"
    },
    {
     "id": "ANA-CHAT",
     "title": "ANA-CHAT",
     "category": "Tenant",
     "severity": "high",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.noForeignValues predicate 1",
       "status": "pass",
       "expected": "Configured JSON predicate holds",
       "actual": "Present; type string; other-tenant identifiers 0; other-tenant attributes 0; echoed identifiers 0; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate pass"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.noForeignValues",
        "present": true,
        "type": "string",
        "outcome": "pass",
        "scan": "complete",
        "counts": {
         "identifiers": 0,
         "attributes": 0,
         "echoed": 0,
         "shared": 0,
         "overlapping": 0,
         "imprecise": 0,
         "partial": 0,
         "unplain": 0,
         "repeatedKeys": 0
        },
        "refs": []
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "Response contract predicates passed; backend effects remain unverified.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "a5a03211-0e51-40bb-9fcd-b69de6b6e15a",
        "actorId": "ana",
        "method": "POST",
        "requestPathHash": "5d4b1ce1ab6fc39a8ced60a839a7d62a4b342f4dee7895d74f67f3963aa84467",
        "routeSegments": [
         {
          "exact": "1fc2a6fa22bdcdacf295c687587eeb6732a73a2e2666621e4dcaf2f112d727a7",
          "keys": []
         },
         {
          "exact": "8e7c6b98c702313e28a7c52aacbebdc7a932cb83779d4249e5f12d15ca098283",
          "keys": [
           "2f8688d50f8fd8b1f232a3d00adfc8d79d0082b1c8f0c04f06f75adfc205f76c",
           "37070cfe6b022b84e1493f2d6b3fc633a4561bcc910c8d6b13ccbe66958c9f4d",
           "c7937119cfa8b3e5f14d6fa439c3a4bfd269dd6fd1aeb4fa159999af9cae3668"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "b16e1da5b1e17b511c37dc0d747aa48947417a172c66aae03ff61308a609757d",
         "bodyKeys": "535bca7636f67dbf5951f1d62d0aa37bc3408debc81d702fe985c9f71785bf03" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 59,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action."
       }
      }
     ],
     "remediation": {
      "title": "Review this application contract",
      "why": "A response predicate is evidence about the response, not proof of a backend effect.",
      "steps": [
       "Review the original private profile and the target implementation.",
       "Apply any repair in the authorized test application.",
       "Retest the unchanged contract and required permitted-use controls."
      ],
      "codePointers": [
       "Local target profile",
       "Check ANA-CHAT"
      ]
     },
     "durationMs": 1,
     "evidenceDigest": "92a83a9f9a02ba1cee1718b0411a8cbadc60cc5274fa5c4edc3424ae3d766fd6",
     "decision": "pass"
    }
   ],
   "identityEvidence": {
    "schema": "actor-identity/6",
    "actors": [
     {
      "actorId": "ana",
      "credentialMode": "bearer",
      "requiredControlIds": [
       "ANA-ME",
       "ANA-OWN"
      ],
      "identityControlIds": [
       "ANA-ME"
      ],
      "surfaceControlIds": [
       "ANA-OWN"
      ],
      "refusesWith401": false,
      "refusalStatuses": [
       401,
       403
      ],
      "before": [
       {
        "controlId": "ANA-ME",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "ANA-OWN",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "between": [
       {
        "afterCheckId": "ANA-OWN",
        "probes": [
         {
          "controlId": "ANA-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "ANA-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       },
       {
        "afterCheckId": "ANA-NO-GLOBEX-ORDER",
        "probes": [
         {
          "controlId": "ANA-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "ANA-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       }
      ],
      "after": [
       {
        "controlId": "ANA-ME",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "ANA-OWN",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "anonymous": [
       {
        "controlId": "ANA-ME",
        "kind": "anonymous",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "invalid": [
       {
        "controlId": "ANA-ME",
        "kind": "invalid",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "cross": [
       {
        "controlId": "ANA-ME",
        "kind": "cross",
        "crossActorId": "gil",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "reason": "established",
      "loginProven": true,
      "established": true
     },
     {
      "actorId": "gil",
      "credentialMode": "bearer",
      "requiredControlIds": [
       "GIL-ME",
       "GIL-OWN"
      ],
      "identityControlIds": [
       "GIL-ME"
      ],
      "surfaceControlIds": [
       "GIL-OWN"
      ],
      "refusesWith401": false,
      "refusalStatuses": [
       401,
       403
      ],
      "before": [
       {
        "controlId": "GIL-ME",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "GIL-OWN",
        "kind": "before",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "between": [
       {
        "afterCheckId": "GIL-OWN",
        "probes": [
         {
          "controlId": "GIL-ME",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [
           {
            "kind": "json.equals",
            "outcome": "pass",
            "identity": true
           }
          ],
          "outcome": "pass"
         },
         {
          "controlId": "GIL-OWN",
          "kind": "between",
          "requestAttempted": true,
          "requestTimeoutMs": 3000,
          "httpStatus": 200,
          "transportOutcome": "complete",
          "statusOutcome": "pass",
          "predicates": [],
          "outcome": "pass"
         }
        ]
       }
      ],
      "after": [
       {
        "controlId": "GIL-ME",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "pass",
          "identity": true
         }
        ],
        "outcome": "pass"
       },
       {
        "controlId": "GIL-OWN",
        "kind": "after",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [],
        "outcome": "pass"
       }
      ],
      "anonymous": [
       {
        "controlId": "GIL-ME",
        "kind": "anonymous",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "invalid": [
       {
        "controlId": "GIL-ME",
        "kind": "invalid",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 401,
        "transportOutcome": "complete",
        "statusOutcome": "fail",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "cross": [
       {
        "controlId": "GIL-ME",
        "kind": "cross",
        "crossActorId": "ana",
        "requestAttempted": true,
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "transportOutcome": "complete",
        "statusOutcome": "pass",
        "predicates": [
         {
          "kind": "json.equals",
          "outcome": "fail",
          "identity": true
         }
        ],
        "outcome": "fail"
       }
      ],
      "reason": "established",
      "loginProven": true,
      "established": true
     }
    ]
   },
   "principals": {
    "ana": "ana-1",
    "gil": "gil-1",
    "anonymous": "anonymous"
   },
   "tenantValueCounts": {
    "attributesAlone": "inconclusive",
    "tenants": [
     {
      "identifiers": 2,
      "attributes": 1
     },
     {
      "identifiers": 2,
      "attributes": 0
     },
     {
      "identifiers": 1,
      "attributes": 0
     }
    ],
    "actorTenants": {
     "ana": 1,
     "gil": 2
    }
   },
   "limitations": [
    "The connector assessed an operator-configured local application using HTTP response predicates; it did not independently observe backend retrieval or tool effects.",
    "Application, actor, build and data-context identities are declared by the profile. The target may have its own model, database or network dependencies.",
    "A passing response contract is not a security certification. Requirements needing backend evidence remain inconclusive when response predicates pass.",
    "Raw request/response content and credentials are not retained. Reproducing a predicate requires the original private profile and comparable target state.",
    "Requests run once without retries or automatic reset. A timed-out POST, PUT, PATCH or DELETE may still have executed; inspect the target before retrying manually.",
    "Other-tenant values (json.noForeignValues): The value at the pointer is read as leaves (every string, every object key, and every JSON number as the response body writes it) under an allowlist rule. It fails only on another tenant's identifier written literally (its exact declared characters, spaces at its ends trimmed) as a whole token, in an occurrence that no value of another set of owner tenants overlaps, that the check's own request does not carry. It passes only when every leaf is in the plain form, the response body repeats no member name, and no other tenant's value occurs in any reading, except that under \"attributesAlone\": \"ignore\" an attribute seen as a whole token does not prevent a pass. Everything else reads inconclusive, never pass. A response body with a repeated member name in any object reads inconclusive, never pass, because JSON parsing keeps only the last of the repeated values (the connector counts repeats on the raw body); another tenant's identifier written literally in the parsed value still fails. The connector also keeps each JSON number's source text, so 7.50, 731e-400 and 12345678901234567 are read with the digits the body shows; a transport that reports neither, and a body nested too deeply for the connector's second parse, read inconclusive unless another tenant's identifier is written literally as a whole token, which still fails. The plain form: ASCII letters and digits, the other letters and decimal digits that occur in some declared value (only those that Unicode assigns to one of these scripts: Latin, Greek, Cyrillic, Armenian, Georgian, Cherokee, Hebrew, Arabic, Syriac, Thaana, NKo, Han with kana and Bopomofo, Hangul, Thai, Lao, Khmer, Myanmar, Devanagari, Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam, Sinhala and Ethiopic; never Common, Inherited or default-ignorable ones; and in a script with letter case only letters that have an uppercase or lowercase partner), U+0020 spaces, U+000A line feeds and the punctuation . , ; : ! ? ' \" ( ) - / @ # $, in a leaf that Unicode NFKC normalization leaves unchanged and that does not hold ASCII digits beside other decimal digits. An object member name that is an array index (0 to 4294967294, written without leading zeros) is outside the form when the object has another member, since JavaScript lists such names first and the body's order of the members is not known. Across the whole value at the pointer, every letter and every number character other than an ASCII digit, in every leaf and in every other tenant's declared values, must be of one script group (Han, kana and Bopomofo count as one; a script not listed counts as a group of its own); otherwise every leaf holding such a character is outside the form, since a reply in one script can show another script's value in look-alike letters. Likewise, when right-to-left letters or digits occur anywhere at the pointer together with left-to-right letters or digits (ASCII digits are left-to-right), or the response body holds anywhere a character of the right-to-left blocks (U+0590 to U+08FF, U+FB1D to U+FDFF, U+FE70 to U+FEFF, U+10800 to U+10FFF, U+1E800 to U+1EFFF) or a bidi control, every leaf at the pointer holding a letter or digit of either direction is outside the form, since the display order of one leaf depends on the text around it. Any escape (a backslash, a percent sign, an HTML entity), any markup character (< > * _ ~ `), any control, format, bidi, default-ignorable or combining character, a compatibility form such as fullwidth letters, any letter or digit no declared value uses (small capitals, IPA letters, spacing modifier letters, letters drawn like punctuation, the katakana long vowel mark, the Arabic tatweel), letters or numbers of two script groups (in the reply, or the reply's and another tenant's values), a tab, a carriage return and any other symbol puts its leaf outside the form, and such a leaf reads inconclusive unless another tenant's identifier is written literally in it (accepted recall loss: replies with curly quotes, markdown, emoji, accents written as combining marks, Indic and Thai text, any accented or non-Latin letter that no declared value uses, katakana words with the long vowel mark, a leaf that mixes scripts, such as a Cyrillic name in an English sentence, and every reply with a letter when other tenants' values use another script group or more than one, such as a Latin reply when another tenant holds a Cyrillic name, read inconclusive). The loose reading keeps only letters and number characters, each after Unicode NFKD decomposition with every combining mark removed, before and after a full case fold (the capital and the small sharp s both read ss), with ligatures and letters with a stroke or bar read as their base letters from a fixed list in src/tenant-values.mjs (æ ae, œ oe, þ th, ø o, ł l, đ d, ħ h, ƶ z, ғ г and others), Hebrew final letters as their base letters, the Persian yeh and keheh, the alef maksura and the teh marbuta as yeh, kaf, yeh and heh, katakana as hiragana, an iteration mark (々, ゝ) as the letter right before it (one with no letter right before it in its leaf reads as nothing and puts the leaf outside the form), the ideographic zero as 0 and every decimal digit as its ASCII digit; a declared value with ä, ö, ü, å or ø is also read with those letters spelled ae, oe, ue, aa and oe, and one with ae, oe, ue or aa also with those written a, o, u and a; a value seen there anywhere but inside its own whole literal occurrence (in another letter case, with its accents removed, with other spacing, punctuation or line breaks between its characters, or glued to more letters or digits) reads inconclusive, never fail. The joined readings are the loose reading with the leaf boundaries removed, in order (array items in order, each object key before its value, object members in JavaScript property order), once over every leaf and once over the leaves that are not object keys; a value seen there across a leaf boundary ([\"REF-\", \"5150\"], {\"REF\": 5150}, {\"first\": \"Grace\", \"last\": \"Hopper\"}) reads inconclusive, never pass. The number readings are the loose reading and the joined readings with the zeros at both ends of every run of ASCII digits removed (a run of zeros vanishes); a value with a digit, read the same way, seen there reads inconclusive, never pass, unless an end of it that is a digit meets, past any zeros written right beside it, another digit written right beside it, so 17310 and 7.51 are other numbers than 731 and 7.5 (\"Order 731\", \"Order 731 2 items\" or \"Order 7.31e2\" for \"00731\", \"7.5\" for \"7.50\", \"INV-42\" for \"INV-0042\", \"1,000\" for \"1000.00\"; accepted recall loss: 7310 reads like 731, 1, 10, 0.1 and 100.00 read alike, and \"ABC\" reads like \"ABC-000\"; a value made of zeros only, such as \"0.00\", has no number reading). A token edge is open at a leaf edge, beside a space or line feed, or beside a run of the listed punctuation that ends at a leaf edge, space or line feed. No edge closes: any other neighbor is glue and reads inconclusive (a letter or digit of any case, a character outside the form, or punctuation that meets a letter or digit: \"orderREF-5150\", \"REF-51501\", \"REF-5150-B\", \"/orders/REF-5150\", \"myjdoe42\" for \"jdoe42\"; accepted recall loss: a longer word that holds a value, such as \"Hoppers\", \"Anne\", \"annual\" or \"Joanna\" for \"Hopper\" and \"Ann\", reads inconclusive too). A value whose first or last character is not a letter or digit (\"@example.net\") has an open edge there unless its neighbor is a character other than a letter, digit, space, line feed or listed punctuation. Also inconclusive: a value the actor's tenant shares with another tenant, an identifier two or more other tenants share (an attribute that only other tenants share counts as an attribute), a value seen only in occurrences that overlap an occurrence of a value with another set of owner tenants (the actor's own \"Grace Hopper\" holding another tenant's \"Hopper\", or another tenant's \"5150\" glued inside the actor's \"REF-5150\"), another tenant's identifier whose loose reading occurs in the request's decoded path, query, body keys, strings or numbers (an echo: \"I can't share REF-5150\" and a reply that returns that record cannot be told apart), a leaf that is a number (a JSON number, or a string of decimal text alone) equal to a declared decimal value written differently, leading zeros included (\"7.50\" for 7.5, \"02134\" for 2134, the string \"7.5\" for \"7.50\"). Declared values with the same loose reading are one value, and it is an identifier when any tenant declares it as one, so the result does not depend on declaration order. A declared value that Unicode NFKC normalization changes (decomposed accents, compatibility forms) is refused. Not seen: a value the profile did not declare, a paraphrase, a value spelled out or written in another spelling than these readings give (\"Mohammed\" for \"Muhammad\"), a value split across leaves in another order or with another leaf between its parts ({\"num\": 5150, \"prefix\": \"REF-\"}), a number rounded to other digits (\"7.49\" for \"7.5\"), a value written in look-alike letters of its own script group, a value with a letter replaced by another letter of the plain form (an accented letter some declared value uses, or an ASCII look-alike such as \"O\" for \"0\"), a number a renderer computes, such as the item numbers of a Markdown ordered list, and a display that sets a right-to-left direction itself. Attributes seen as whole tokens on their own read inconclusive by default, or are ignored under \"attributesAlone\": \"ignore\"; an attribute seen only partially, or only as a number written differently, reads inconclusive under either policy. The scan reads at most 131072 characters (524288 in its loose reading) and judges at most 262144 matches; past either bound it reads inconclusive. Saved evidence names a matched value only by its position in the profile (tenant n, identifier m), never by the value.",
    "A credentialed actor's login counts only with positive evidence in the same run: a required GET control returning its declared identity, refused without a credential, with an invalid credential (a random look-alike of the actor's own, made fresh each run) and with each other actor's credential, and passing again with the actor's surface controls (its other required GET controls, on protected routes) at a probe point before the actor's first other check and after each of them, each probe in full. Identity is judged per check (actor-identity/5): a check rests on that identity route proof and on the two probe points around it. A point that did not pass withholds the checks it covers, ranked across both of a check's points, except that a required control is withheld only for a login-level reason (an identity probe that did not pass or did not finish at a point covering it, or a probe refused at any point), never because a surface probe failed for another reason; a check whose own two points passed keeps its status when another point fails. A probe refused with the actor's own credential at any point withholds every check of the actor, required and identity controls included, since a credential that flaps can be refused between two accepting points: a refused identity probe (401, 403, its declared sign-in redirect, or a complete 2xx that names another principal or none) reads bracket-not-passed, a refused surface probe (401, 403 or the declared redirect: the protected routes did not accept the credential the identity route accepted) reads surface-refused, and bracket-not-passed when both were refused. A surface probe that fails otherwise (a 500, a 404) leaves the checks its point covers not established. A withheld check is inconclusive; a boundary check whose refusal was observed while its identity or allowed use was not established is the distinct decision prohibition-observed-identity-unproven, never a pass. The gate reports identity-not-established for an actor whose route or any point did not hold, and a comparison never labels a row restored or fixed when its identity was not proven for it. A credentialed 401 on a boundary check is an authentication failure, not a refusal, unless the actor declares refusesWith401 and a surface control brackets its checks. A 403 or any other answer outside 2xx counts as a refusal only after the same actor's complete 2xx on a protected route (a surface control in its probe points); without one it is inconclusive. An outage strictly between the two probe points that cover a check is not detected. Evidence of credential loss on an actor's own main rows, rather than at a probe point, stays row-level: a credentialed 401 on a boundary check (unauthenticated-401), a redirect to the declared sign-in, or a required control answering a refusal status withholds or fails that row, and the gate fails, but a comparison may still credit other rows of that actor, and a change or a captured value that actor made still counts as attributed."
   ]
  }
 }
};
