// An HTTP run recorded and sealed at main 8ecfe737 (before pg_net on the wire) by main's own connector: a pg-wal observer with no pgNetWire
// over pg-wal's scripted session in which pg_net's unlogged queue exists; suite is the suite main exported for the profile.
// test/pg-wal-profile.test.mjs validates it at the head. Synthetic data, loopback only, no credential values. The object is the
// recorder's JSON verbatim; edit nothing, or the seal no longer holds.
export default {
 "recordedAt": "8ecfe737",
 "note": "An HTTP run recorded and sealed at main 8ecfe737, before pg_net on the wire, by main's own connector: a pg-wal observer (platform supabase, no pgNetWire) over pg-wal's scripted session in which pg_net's unlogged request queue exists, so the database-only absence reads inconclusive (table-not-in-wal); suite is the suite main exported for the profile. test/pg-wal-profile.test.mjs validates it at the head. Synthetic data, loopback only; no credential values.",
 "profile": {
  "id": "refunds-pgnet",
  "name": "Refunds (pg_net installed)",
  "applicationId": "refunds-app",
  "origin": "http://127.0.0.1:64312",
  "buildLabel": "b1",
  "contextId": "synthetic-refunds",
  "actors": {
   "bob": {
    "principalId": "bob",
    "credentialEnv": "SCOPEHAVEN_TARGET_BOB",
    "identityValue": "bob"
   }
  },
  "requiredControlIds": [
   "WHOAMI"
  ],
  "observers": [
   {
    "id": "wal",
    "type": "pg-wal",
    "host": "127.0.0.1",
    "port": 5432,
    "database": "app",
    "credentialEnv": "SCOPEHAVEN_TARGET_WAL",
    "settleMs": 250,
    "tables": [
     {
      "table": "orders",
      "key": "id",
      "values": [
       "status",
       "amount"
      ]
     }
    ],
    "platform": "supabase",
    "barrierMs": 100
   }
  ],
  "checks": [
   {
    "id": "WHOAMI",
    "title": "Who am I",
    "category": "identity",
    "severity": "control",
    "actorId": "bob",
    "method": "GET",
    "path": "/me",
    "evidenceRequirement": "response",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     },
     {
      "kind": "json.equals",
      "pointer": "/user",
      "expected": "bob"
     }
    ]
   },
   {
    "id": "REFUND",
    "title": "Bob refunds order a",
    "category": "allowed-use",
    "severity": "control",
    "actorId": "bob",
    "method": "PATCH",
    "path": "/orders/a/refund",
    "evidenceRequirement": "backend",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     }
    ],
    "effects": [
     {
      "kind": "effect.exists",
      "select": {
       "source": "sql-wal",
       "name": "orders",
       "operation": "update",
       "resource": "orders/a"
      }
     }
    ]
   },
   {
    "id": "NO-REFUND-ON-READ",
    "title": "Reading an order refunds nothing (database only)",
    "category": "object-access",
    "severity": "high",
    "actorId": "bob",
    "method": "GET",
    "path": "/orders/a",
    "evidenceRequirement": "backend",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 200
     }
    ],
    "effects": [
     {
      "kind": "effect.none",
      "select": {
       "source": "sql-wal",
       "name": "orders",
       "operation": "update",
       "resource": "orders/a"
      }
     }
    ]
   }
  ]
 },
 "suite": {
  "id": "refunds-pgnet-contracts",
  "targetId": "refunds-pgnet",
  "applicationId": "refunds-app",
  "version": "http-contract/4",
  "evidenceOrigin": "local-http-response",
  "hash": "0c7ad8664ed60b5097bb7e4620f3d473d195920f7c1d16553becd4e00d1ffe65",
  "scope": "Definition summary only; private request bodies, expected values, actor credentials and endpoints are omitted.",
  "requiredControlIds": [
   "WHOAMI"
  ],
  "checks": [
   {
    "id": "WHOAMI",
    "title": "Who am I",
    "category": "identity",
    "severity": "control",
    "evidenceRequirement": "response",
    "method": "GET",
    "assertionKinds": [
     "status.equals",
     "json.equals"
    ],
    "actorId": "bob",
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
    "id": "REFUND",
    "title": "Bob refunds order a",
    "category": "allowed-use",
    "severity": "control",
    "evidenceRequirement": "backend",
    "method": "PATCH",
    "assertionKinds": [
     "status.equals"
    ],
    "actorId": "bob",
    "credentialMode": "bearer",
    "effects": [
     {
      "kind": "effect.exists",
      "select": {
       "source": "sql-wal",
       "name": "orders",
       "operation": "update",
       "resource": "orders/a"
      }
     }
    ],
    "recordPredicates": []
   },
   {
    "id": "NO-REFUND-ON-READ",
    "title": "Reading an order refunds nothing (database only)",
    "category": "object-access",
    "severity": "high",
    "evidenceRequirement": "backend",
    "method": "GET",
    "assertionKinds": [
     "status.equals"
    ],
    "actorId": "bob",
    "credentialMode": "bearer",
    "effects": [
     {
      "kind": "effect.none",
      "select": {
       "source": "sql-wal",
       "name": "orders",
       "operation": "update",
       "resource": "orders/a"
      }
     }
    ],
    "recordPredicates": []
   }
  ],
  "identitySchema": "actor-identity/6",
  "catalogSchema": "scopehaven-catalog-identity/1",
  "catalogObservers": [
   "pg-wal-wal"
  ],
  "principalsDigest": "fdb95bebfd1a9b77fe2ef0f6ddca611f150431f9ee7c06f97abba576925958b2",
  "observers": [
   {
    "id": "wal",
    "type": "pg-wal",
    "settleMs": 250,
    "collector": {
     "label": "pg-wal/4",
     "digest": "f50b799a005f26feaf461cec3ae7dc49d284ccbb880e2d26781a419e6e55e14a",
     "node": "24.21.0"
    }
   }
  ],
  "targetContext": "local-app",
  "targetLabel": null,
  "runnableWith": "Use the original local profile with ./scopehaven assess --config <file> --target <id>. This redacted summary is not an executable profile."
 },
 "run": {
  "schemaVersion": 1,
  "id": "788b2668-a030-46ba-acb9-07102e4e1afd",
  "createdAt": "2026-10-27T08:18:36.360Z",
  "targetId": "refunds-pgnet",
  "targetName": "Refunds (pg_net installed)",
  "build": "b1",
  "applicationId": "refunds-app",
  "suiteId": "refunds-pgnet-contracts",
  "suiteHash": "4abf7c8fb6037caa9da17796b0b4b9697d809c4907c40e3822744f95d27886e1",
  "policyHash": "4abf7c8fb6037caa9da17796b0b4b9697d809c4907c40e3822744f95d27886e1",
  "profileHash": "0c7ad8664ed60b5097bb7e4620f3d473d195920f7c1d16553becd4e00d1ffe65",
  "contextId": "synthetic-refunds",
  "fixtureVersion": "operator-declared-context/1",
  "fixtureHash": "da08ca1c06bd3eea5f85adf2794d597e9ee886f635b665e7bc38e8a8c2986bca",
  "adapterVersion": "loopback-response-contract/3",
  "assertionSchemaVersion": "http-contract/4",
  "evaluatorHash": "b1c4a90d0b49fadc0a11da2cf87d81dbad5893e60cff301aee17cbeabd1ab5d4",
  "requiredControlIds": [
   "WHOAMI"
  ],
  "evidenceOrigin": "local-http-response",
  "runtimeMode": "configured-local-application",
  "targetBuildHash": null,
  "targetConfigHash": "8f7e1548714257dfbd4f57e52efa034fba2cb6680e78c3e96f296adbc3143ada",
  "buildIdentity": "Declared in configuration; not independently attested.",
  "targetContext": "local-app",
  "targetLabel": null,
  "scopeLabel": "HTTP response contracts plus declared observers. Backend effects count only where an authoritative observer decided them. Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: wal 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
  "observers": [
   {
    "id": "wal",
    "type": "pg-wal",
    "settleMs": 250,
    "collector": {
     "label": "pg-wal/4",
     "digest": "f50b799a005f26feaf461cec3ae7dc49d284ccbb880e2d26781a419e6e55e14a",
     "node": "24.21.0"
    }
   }
  ],
  "settlement": {
   "schema": "scopehaven-settlement/1",
   "settleMs": 250,
   "gaps": [
    {
     "after": null,
     "before": "REFUND",
     "windows": [
      {
       "source": "sql-wal",
       "instanceId": "pg-wal-wal",
       "scope": {
        "operations": [
         "insert",
         "update",
         "delete"
        ],
        "names": [
         "orders"
        ],
        "actorAttribution": "none",
        "evidence": "authoritative"
       },
       "coverage": "partial",
       "reason": "table-not-in-wal",
       "events": [],
       "settleMs": 250,
       "lineage": {
        "observer": "postgres-wal-decode",
        "independence": "database-log"
       }
      }
     ]
    },
    {
     "after": "REFUND",
     "before": "NO-REFUND-ON-READ",
     "windows": [
      {
       "source": "sql-wal",
       "instanceId": "pg-wal-wal",
       "scope": {
        "operations": [
         "insert",
         "update",
         "delete"
        ],
        "names": [
         "orders"
        ],
        "actorAttribution": "none",
        "evidence": "authoritative"
       },
       "coverage": "partial",
       "reason": "table-not-in-wal",
       "events": [],
       "settleMs": 250,
       "lineage": {
        "observer": "postgres-wal-decode",
        "independence": "database-log"
       }
      }
     ]
    },
    {
     "after": "NO-REFUND-ON-READ",
     "before": null,
     "windows": [
      {
       "source": "sql-wal",
       "instanceId": "pg-wal-wal",
       "scope": {
        "operations": [
         "insert",
         "update",
         "delete"
        ],
        "names": [
         "orders"
        ],
        "actorAttribution": "none",
        "evidence": "authoritative"
       },
       "coverage": "partial",
       "reason": "table-not-in-wal",
       "events": [],
       "settleMs": 250,
       "lineage": {
        "observer": "postgres-wal-decode",
        "independence": "database-log"
       }
      }
     ]
    }
   ]
  },
  "catalog": {
   "schema": "scopehaven-catalog-identity/1",
   "sha256": "f45dfb0a744380a848b05a20d574ac6af2a84261ecc7f7f4858a3fff8e91a150",
   "observers": [
    {
     "schema": "scopehaven-catalog/1",
     "engine": "postgres",
     "sha256": "1aac2a403614b2e4371ee9d05f986451dc27cd5e1da183baddb9781b526ad162",
     "kinds": {
      "schema": {
       "objects": 1,
       "sha256": "efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7"
      },
      "relation": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "column": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "constraint": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "index": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "policy": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "trigger": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "rule": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "function": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "type": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "extension": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "event-trigger": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "foreign-server": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "publication": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "default-acl": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "operator": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "cast": {
       "objects": 0,
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
     },
     "final": "1aac2a403614b2e4371ee9d05f986451dc27cd5e1da183baddb9781b526ad162",
     "changedDuringRun": false,
     "excluded": {
      "schemas": [
       "_analytics",
       "_realtime",
       "_supavisor",
       "supabase_migrations"
      ],
      "tables": []
     },
     "instanceId": "pg-wal-wal"
    }
   ]
  },
  "durationMs": 816,
  "checksTotal": 3,
  "counts": {
   "pass": 2,
   "fail": 0,
   "inconclusive": 1,
   "error": 0,
   "not_applicable": 0
  },
  "results": [
   {
    "id": "WHOAMI",
    "title": "Who am I",
    "category": "identity",
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
       "requestId": "2fd5c840-042a-4347-8a96-2df3e6f37eb2",
       "actorId": "bob",
       "method": "GET",
       "requestPathHash": "b4104b822236e8acba1cec3b8531cb785a5a11300e229b22306ba70151590fe2",
       "routeSegments": [
        {
         "exact": "a6e09d1397e6d00259b9d8940d2a2439ab8395c0e5c9c653a57b72192cb09bd8",
         "keys": [
          "add30ec438bbd36bc430aa70d7e22b8e1a17d3900e0bc09eb2ab47bd8b7a94ab"
         ]
        }
       ],
       "controlScope": {
        "cleanObject": true,
        "recordPredicates": [],
        "sentRoute": "73faa73404d95fd8c73680dc4512344025be3434ffd3b3e1b17f99c5071a6b78",
        "bodyKeys": "73eba14ae284a8c06da4add40196ecb562b0131f94e8770d5c68f3db82577330" // gitleaks:allow: a sha256 digest of the request body's key names that main's connector sealed into the run, not a credential
       },
       "credentialMode": "bearer",
       "requestTimeoutMs": 3000,
       "httpStatus": 200,
       "responseComplete": true,
       "responseBytes": 14,
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
      "Check WHOAMI"
     ]
    },
    "durationMs": 11,
    "evidenceDigest": "286b947563e5a414eeea306043ffa1665d3ccbf317cc32470d2b9ed959eeee56",
    "decision": "pass"
   },
   {
    "id": "REFUND",
    "title": "Bob refunds order a",
    "category": "allowed-use",
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
      "name": "Trusted backend observation available",
      "status": "pass",
      "expected": "Independent backend evidence required",
      "actual": "Authoritative observers decided every declared effect"
     },
     {
      "name": "Observed effect 1 (effect.exists)",
      "status": "pass",
      "expected": "A matching committed effect",
      "actual": "pass: An observer recorded the expected committed effect.",
      "custody": "subject-writable"
     }
    ],
    "observed": {
     "httpStatus": 200,
     "complete": true,
     "jsonParsed": true,
     "predicates": [],
     "evidenceScope": "response-and-observers"
    },
    "summary": "Response predicates and observed effects passed.",
    "evidenceRequirement": "backend",
    "expected": "Configured response predicates and independent backend evidence.",
    "backendEvidence": "observed",
    "trace": [
     {
      "type": "http-observation",
      "label": "Retained response metadata; response content is not stored",
      "data": {
       "requestId": "f0378203-5a97-43ec-b8b8-b43f55cff7a4",
       "actorId": "bob",
       "method": "PATCH",
       "requestPathHash": "c22001931deff4215eacfc3effa41b4f3bd43382d3bb107ffe4d74f53f803399",
       "routeSegments": [
        {
         "exact": "e6e5e1942f4eab812055d6b4a131d671bc27bded24d65a04e1286e82f9af6c2e",
         "keys": [
          "1a68be5007af27464d968f9aefe5e5eecf63d84ef9fcbb041cd5eef8ab01ad09",
          "1bdffa73e028d52c9390c3d36408bb3763b16f3bddce55db6678bca8b5516a47",
          "786c35c2142737b2e25efe35de0390d2abf2c97c2832a18a28186ee018feb6e7",
          "d6c3ba7580b003ad0cc322612befe23b6cc0bdeec12b4ba8cffb20ea250a5d27"
         ]
        },
        {
         "exact": "d04d146b49ec0a6f5805d531d8eb2d0016548f95d2850513bba994d0c9570e82",
         "keys": [
          "a61642ac98ab3b46f1ac9ccc890cabf138aa144f5def6f2c8eddd1ef4af5c0dd"
         ]
        },
        {
         "exact": "a0d246c75350f4419cd2ce4044e7db22c91f39312623bab18309fa6ecfb082ce",
         "keys": [
          "28837352a0e82fde982dda8303c4e5d73911863fe88e5fb82cce7446019019d2",
          "65105c758d4757675bc632fece0ae0136b5400d5fabf308601342664e155644e",
          "81fa86358345e09e61ab4e14de55994506882b61715080a6dbc837a807ed7d0e",
          "969df1c37c3fa3f618853f2111b8008dcee659276d56645e1af18b9413c49a0e",
          "a191f6c5fdcfd4a37ffe9062a3d5fabe265b61d5a1352213845551b1002b0aa1"
         ]
        }
       ],
       "controlScope": {
        "cleanObject": false,
        "recordPredicates": [],
        "sentRoute": "9a96e25861bcc855cc8f6f475d4e90eef80a870fa221df24252acc4c5757658d",
        "bodyKeys": null
       },
       "credentialMode": "bearer",
       "requestTimeoutMs": 3000,
       "httpStatus": 200,
       "responseComplete": true,
       "responseBytes": 11,
       "jsonParsed": true,
       "transportOutcome": "complete",
       "backendEvidence": "unavailable",
       "requestAttempted": true,
       "mutationEffects": "Not independently observed; a timeout does not undo an action."
      }
     },
     {
      "type": "effect-observation",
      "label": "Independent observer windows for this check; events carry identifiers and digests, plus declared captured body fields where an observer declares them",
      "data": {
       "schema": "scopehaven-effect-evidence/1",
       "effects": [
        {
         "kind": "effect.exists",
         "select": {
          "source": "sql-wal",
          "name": "orders",
          "operation": "update",
          "resource": "orders/a"
         },
         "verdict": "pass",
         "matched": 1,
         "custody": "subject-writable"
        }
       ],
       "windows": [
        {
         "source": "sql-wal",
         "instanceId": "pg-wal-wal",
         "scope": {
          "operations": [
           "insert",
           "update",
           "delete"
          ],
          "names": [
           "orders"
          ],
          "actorAttribution": "none",
          "evidence": "authoritative"
         },
         "coverage": "partial",
         "reason": "table-not-in-wal",
         "events": [
          {
           "schema": "scopehaven-effect/1",
           "source": "sql-wal",
           "observer": {
            "kind": "postgres-wal-decode",
            "instanceId": "pg-wal-wal"
           },
           "seq": 1,
           "observedAt": "2026-10-27T08:18:35.820Z",
           "actor": null,
           "operation": "update",
           "name": "orders",
           "resource": "orders/a",
           "outcome": "committed",
           "correlation": {},
           "contentDigest": "ea3a69b401a4d9464d7e9efc1916250eabb079efa2842a33d5735cbff3288b89"
          }
         ],
         "settleMs": 250,
         "lineage": {
          "observer": "postgres-wal-decode",
          "independence": "database-log"
         }
        }
       ]
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
      "Check REFUND"
     ]
    },
    "durationMs": 261,
    "evidenceDigest": "13195c185599d8cb799439fce639877868ac33acb3a6f8c4a49dd09020527d5e",
    "decision": "pass"
   },
   {
    "id": "NO-REFUND-ON-READ",
    "title": "Reading an order refunds nothing (database only)",
    "category": "object-access",
    "severity": "high",
    "status": "inconclusive",
    "assertions": [
     {
      "name": "HTTP status matches contract",
      "status": "pass",
      "expected": "HTTP 200",
      "actual": "HTTP 200"
     },
     {
      "name": "Trusted backend observation available",
      "status": "inconclusive",
      "expected": "Independent backend evidence required",
      "actual": "Backend evidence unavailable"
     },
     {
      "name": "Observed effect 1 (effect.none)",
      "status": "inconclusive",
      "expected": "No matching committed effect",
      "actual": "missing: Not every authoritative observer that can see this effect covered the window (pg-wal-wal: partial, table-not-in-wal).",
      "custody": null
     }
    ],
    "observed": {
     "httpStatus": 200,
     "complete": true,
     "jsonParsed": true,
     "predicates": [],
     "evidenceScope": "response-and-observers"
    },
    "summary": "A response predicate or an observed effect could not be decided.",
    "evidenceRequirement": "backend",
    "expected": "Configured response predicates and independent backend evidence.",
    "backendEvidence": "unavailable",
    "trace": [
     {
      "type": "http-observation",
      "label": "Retained response metadata; response content is not stored",
      "data": {
       "requestId": "e142e601-dde5-41eb-9493-6d4dc8bc0142",
       "actorId": "bob",
       "method": "GET",
       "requestPathHash": "25fe5ecf81c7e54d73cce6a1d0a89f53a240a7b0499c7569a20481294cb58790",
       "routeSegments": [
        {
         "exact": "e6e5e1942f4eab812055d6b4a131d671bc27bded24d65a04e1286e82f9af6c2e",
         "keys": [
          "1a68be5007af27464d968f9aefe5e5eecf63d84ef9fcbb041cd5eef8ab01ad09",
          "1bdffa73e028d52c9390c3d36408bb3763b16f3bddce55db6678bca8b5516a47",
          "786c35c2142737b2e25efe35de0390d2abf2c97c2832a18a28186ee018feb6e7",
          "d6c3ba7580b003ad0cc322612befe23b6cc0bdeec12b4ba8cffb20ea250a5d27"
         ]
        },
        {
         "exact": "d04d146b49ec0a6f5805d531d8eb2d0016548f95d2850513bba994d0c9570e82",
         "keys": [
          "a61642ac98ab3b46f1ac9ccc890cabf138aa144f5def6f2c8eddd1ef4af5c0dd"
         ]
        }
       ],
       "controlScope": {
        "cleanObject": true,
        "recordPredicates": [],
        "sentRoute": "634dbc7b89598f10c420aa42534333cedede9e969cc3e77ffc7e1ab45fa59e83",
        "bodyKeys": "34cbc1132052c488c572e9c09a2f366edce2ecde80112d477f2302f573382bfb" // gitleaks:allow: a sha256 digest of the request body's key names that main's connector sealed into the run, not a credential
       },
       "credentialMode": "bearer",
       "requestTimeoutMs": 3000,
       "httpStatus": 200,
       "responseComplete": true,
       "responseBytes": 10,
       "jsonParsed": true,
       "transportOutcome": "complete",
       "backendEvidence": "unavailable",
       "requestAttempted": true,
       "mutationEffects": "Not independently observed."
      }
     },
     {
      "type": "effect-observation",
      "label": "Independent observer windows for this check; events carry identifiers and digests, plus declared captured body fields where an observer declares them",
      "data": {
       "schema": "scopehaven-effect-evidence/1",
       "effects": [
        {
         "kind": "effect.none",
         "select": {
          "source": "sql-wal",
          "name": "orders",
          "operation": "update",
          "resource": "orders/a"
         },
         "verdict": "missing",
         "matched": 0,
         "custody": null
        }
       ],
       "windows": [
        {
         "source": "sql-wal",
         "instanceId": "pg-wal-wal",
         "scope": {
          "operations": [
           "insert",
           "update",
           "delete"
          ],
          "names": [
           "orders"
          ],
          "actorAttribution": "none",
          "evidence": "authoritative"
         },
         "coverage": "partial",
         "reason": "table-not-in-wal",
         "events": [],
         "settleMs": 250,
         "lineage": {
          "observer": "postgres-wal-decode",
          "independence": "database-log"
         }
        }
       ]
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
      "Check NO-REFUND-ON-READ"
     ]
    },
    "durationMs": 256,
    "evidenceDigest": "7e413db1b680b7188f7a94635f16f5c07c5feb2f99b862757d00ca4154616c27",
    "decision": "inconclusive"
   }
  ],
  "identityEvidence": {
   "schema": "actor-identity/6",
   "actors": [
    {
     "actorId": "bob",
     "credentialMode": "bearer",
     "requiredControlIds": [
      "WHOAMI"
     ],
     "identityControlIds": [
      "WHOAMI"
     ],
     "surfaceControlIds": [],
     "refusesWith401": false,
     "refusalStatuses": [
      401,
      403
     ],
     "before": [
      {
       "controlId": "WHOAMI",
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
      }
     ],
     "between": [
      {
       "afterCheckId": "REFUND",
       "probes": [
        {
         "controlId": "WHOAMI",
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
        }
       ]
      }
     ],
     "after": [
      {
       "controlId": "WHOAMI",
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
      }
     ],
     "anonymous": [
      {
       "controlId": "WHOAMI",
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
       "controlId": "WHOAMI",
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
     "cross": [],
     "reason": "established",
     "loginProven": true,
     "established": true
    }
   ]
  },
  "principals": {
   "bob": "bob"
  },
  "limitations": [
   "The connector assessed an operator-configured local application using HTTP response predicates; it did not independently observe backend retrieval or tool effects.",
   "Application, actor, build and data-context identities are declared by the profile. The target may have its own model, database or network dependencies.",
   "A passing response contract is not a security certification. Requirements needing backend evidence remain inconclusive when response predicates pass.",
   "Raw request/response content and credentials are not retained. Reproducing a predicate requires the original private profile and comparable target state.",
   "Requests run once without retries or automatic reset. A timed-out POST, PUT, PATCH or DELETE may still have executed; inspect the target before retrying manually.",
   "Postgres WAL observers (wal) read every change the server committed to each declared table between two marks from its write-ahead log, through a temporary test_decoding slot their own session holds (no publication, nothing on the target changes): writes made and undone between the marks and exact inserts and deletes are seen, and an absence passes only on the observed tables, never as \"nothing else changed\". They do not see reads, caches, files, direct external calls, LISTEN/NOTIFY, large objects, sequences, DDL (caught only as catalog drift), unlogged or temporary tables, other databases, or jobs that finish after the end mark unless declared as queues; a lost slot or session, removed WAL, an end barrier not reached, catalog drift, an in-flight writer on an observed table, a TRUNCATE or a key the WAL does not carry reads inconclusive, never a pass.",
   "Observed effects are judged from the declared observers only. Traces and tool-call logs can show an effect happened; only an audit log, the application database or the request-path gate can show it did not, and a missing or presence-only observer leaves the effect unverifiable, never a pass.",
   "Custody: in a boundary check (any severity except control), an observed effect passes only when an observer that decided it keeps its record outside the application (the hold gate, an egress recorder or an SMTP sink). One decided only by records the application can write (its audit logs, its database, its traces or tool-call logs) reads inconclusive. Allowed-use controls keep their verdicts and carry custody as a tag only: a record the application can write may show an allowed action happened when it did not.",
   "Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: wal 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
   "A credentialed actor's login counts only with positive evidence in the same run: a required GET control returning its declared identity, refused without a credential, with an invalid credential (a random look-alike of the actor's own, made fresh each run) and with each other actor's credential, and passing again with the actor's surface controls (its other required GET controls, on protected routes) at a probe point before the actor's first other check and after each of them, each probe in full. Identity is judged per check (actor-identity/5): a check rests on that identity route proof and on the two probe points around it. A point that did not pass withholds the checks it covers, ranked across both of a check's points, except that a required control is withheld only for a login-level reason (an identity probe that did not pass or did not finish at a point covering it, or a probe refused at any point), never because a surface probe failed for another reason; a check whose own two points passed keeps its status when another point fails. A probe refused with the actor's own credential at any point withholds every check of the actor, required and identity controls included, since a credential that flaps can be refused between two accepting points: a refused identity probe (401, 403, its declared sign-in redirect, or a complete 2xx that names another principal or none) reads bracket-not-passed, a refused surface probe (401, 403 or the declared redirect: the protected routes did not accept the credential the identity route accepted) reads surface-refused, and bracket-not-passed when both were refused. A surface probe that fails otherwise (a 500, a 404) leaves the checks its point covers not established. A withheld check is inconclusive; a boundary check whose refusal was observed while its identity or allowed use was not established is the distinct decision prohibition-observed-identity-unproven, never a pass. The gate reports identity-not-established for an actor whose route or any point did not hold, and a comparison never labels a row restored or fixed when its identity was not proven for it. A credentialed 401 on a boundary check is an authentication failure, not a refusal, unless the actor declares refusesWith401 and a surface control brackets its checks. A 403 or any other answer outside 2xx counts as a refusal only after the same actor's complete 2xx on a protected route (a surface control in its probe points); without one it is inconclusive. An outage strictly between the two probe points that cover a check is not detected. Evidence of credential loss on an actor's own main rows, rather than at a probe point, stays row-level: a credentialed 401 on a boundary check (unauthenticated-401), a redirect to the declared sign-in, or a required control answering a refusal status withholds or fails that row, and the gate fails, but a comparison may still credit other rows of that actor, and a change or a captured value that actor made still counts as attributed."
  ]
 }
};
