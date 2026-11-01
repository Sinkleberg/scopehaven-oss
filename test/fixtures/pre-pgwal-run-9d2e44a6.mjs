// An HTTP run recorded and sealed at main 9d2e44a6 (before NC9 item 4, PR521) by main's own connector: a pg-snapshot observer over the
// scripted fake Postgres and an unpinned effect.none update, so its degraded row carries the custody text main wrote; suite is the suite
// main exported for the profile. test/pg-wal-profile.test.mjs validates it at the head. Synthetic data, loopback only, no credential
// values. The object is the recorder's JSON verbatim (a module only so that the one sealed digest gitleaks reads as a key can carry its
// allow note); edit nothing, or the seal no longer holds.
export default {
 "recordedAt": "9d2e44a6",
 "note": "An HTTP run recorded and sealed at this main commit, before NC9 item 4 (PR521): a pg-snapshot observer over the scripted fake Postgres and an unpinned effect.none update, so its degraded row carries the custody text main wrote; suite is the suite main exported for the profile. test/pg-wal-profile.test.mjs validates it at the head. Synthetic data, loopback only; no credential values.",
 "profile": {
  "id": "chatbot",
  "name": "Chatbot",
  "applicationId": "chatbot-app",
  "origin": "http://127.0.0.1:51263",
  "buildLabel": "b1",
  "contextId": "synthetic-chatbot",
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
    "id": "db",
    "type": "pg-snapshot",
    "host": "127.0.0.1",
    "port": 51264,
    "database": "app",
    "credentialEnv": "SCOPEHAVEN_TARGET_DB_READER",
    "tables": [
     {
      "table": "Chat",
      "key": "id"
     }
    ],
    "settleMs": 250
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
    "id": "BOB-ALICE-CHAT",
    "title": "Bob cannot read alice's chat, and the read changes nothing",
    "category": "object-access",
    "severity": "high",
    "actorId": "bob",
    "method": "GET",
    "path": "/chats/c1/messages",
    "evidenceRequirement": "backend",
    "assertions": [
     {
      "kind": "status.equals",
      "expected": 403
     }
    ],
    "effects": [
     {
      "kind": "effect.none",
      "select": {
       "source": "sql-snapshot",
       "name": "Chat",
       "operation": "update",
       "resource": "Chat/c1"
      }
     }
    ]
   }
  ]
 },
 "suite": {
  "id": "chatbot-contracts",
  "targetId": "chatbot",
  "applicationId": "chatbot-app",
  "version": "http-contract/4",
  "evidenceOrigin": "local-http-response",
  "hash": "47bbf66ea82579fc73924312142d0161a37b140bcbd10e292f28b0d39cff866f",
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
    "id": "BOB-ALICE-CHAT",
    "title": "Bob cannot read alice's chat, and the read changes nothing",
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
       "source": "sql-snapshot",
       "name": "Chat",
       "operation": "update",
       "resource": "Chat/c1"
      }
     }
    ],
    "recordPredicates": []
   }
  ],
  "identitySchema": "actor-identity/6",
  "catalogSchema": "scopehaven-catalog-identity/1",
  "catalogObservers": [
   "pg-snapshot-db"
  ],
  "principalsDigest": "fdb95bebfd1a9b77fe2ef0f6ddca611f150431f9ee7c06f97abba576925958b2",
  "observers": [
   {
    "id": "db",
    "type": "pg-snapshot",
    "settleMs": 250,
    "collector": {
     "label": "pg-snapshot/4",
     "digest": "8068e0be7eb7e4c7a22948c84a2ec131aa2c0547971a578da394d63fb1d4416c",
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
  "id": "5cedccc3-ae2d-4591-a2e2-1763f61b48b6",
  "createdAt": "2026-10-25T15:55:19.205Z",
  "targetId": "chatbot",
  "targetName": "Chatbot",
  "build": "b1",
  "applicationId": "chatbot-app",
  "suiteId": "chatbot-contracts",
  "suiteHash": "b52cf83f3e716780539e7b75cdffcc814caddfd61eeab5eddd3008c9e59e1c4b",
  "policyHash": "b52cf83f3e716780539e7b75cdffcc814caddfd61eeab5eddd3008c9e59e1c4b",
  "profileHash": "47bbf66ea82579fc73924312142d0161a37b140bcbd10e292f28b0d39cff866f",
  "contextId": "synthetic-chatbot",
  "fixtureVersion": "operator-declared-context/1",
  "fixtureHash": "501f93242a7d55e42e066b2288ec9e2c887f4ae58b0656eafa0e008b1228346d",
  "adapterVersion": "loopback-response-contract/3",
  "assertionSchemaVersion": "http-contract/4",
  "evaluatorHash": "3a7f10c7bacc6aeec41a347a546958e4894b8acf7e55ecb3b4f4211d2937a884",
  "requiredControlIds": [
   "WHOAMI"
  ],
  "evidenceOrigin": "local-http-response",
  "runtimeMode": "configured-local-application",
  "targetBuildHash": null,
  "targetConfigHash": "277866967216cdbb02e84bf3ac3561431a7120e33342ba2005d20950d6496410",
  "buildIdentity": "Declared in configuration; not independently attested.",
  "targetContext": "local-app",
  "targetLabel": null,
  "scopeLabel": "HTTP response contracts plus declared observers. Backend effects count only where an authoritative observer decided them. Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: db 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
  "observers": [
   {
    "id": "db",
    "type": "pg-snapshot",
    "settleMs": 250,
    "collector": {
     "label": "pg-snapshot/4",
     "digest": "8068e0be7eb7e4c7a22948c84a2ec131aa2c0547971a578da394d63fb1d4416c",
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
     "before": "BOB-ALICE-CHAT",
     "windows": [
      {
       "source": "sql-snapshot",
       "instanceId": "pg-snapshot-db",
       "scope": {
        "operations": [
         "insert",
         "update",
         "delete"
        ],
        "names": [
         "Chat"
        ],
        "actorAttribution": "none",
        "evidence": "authoritative"
       },
       "coverage": "net-only",
       "reason": "net-change-between-snapshots",
       "events": [],
       "exact": [
        {
         "name": "Chat",
         "method": "xmin",
         "auditSha256": null,
         "ambiguousResources": [],
         "presentResources": [
          "Chat/c1"
         ],
         "marks": {
          "startXmax": "800",
          "endXmax": "800",
          "inProgress": 0
         },
         "quiescent": true,
         "violated": false,
         "basis": "row versions (xmin) of public.Chat: every committed update writes a new xmin; 0 ambiguous rows"
        }
       ],
       "settleMs": 250,
       "lineage": {
        "observer": "postgres-snapshot-diff",
        "independence": "application-store"
       }
      }
     ]
    },
    {
     "after": "BOB-ALICE-CHAT",
     "before": null,
     "windows": [
      {
       "source": "sql-snapshot",
       "instanceId": "pg-snapshot-db",
       "scope": {
        "operations": [
         "insert",
         "update",
         "delete"
        ],
        "names": [
         "Chat"
        ],
        "actorAttribution": "none",
        "evidence": "authoritative"
       },
       "coverage": "net-only",
       "reason": "net-change-between-snapshots",
       "events": [],
       "exact": [
        {
         "name": "Chat",
         "method": "xmin",
         "auditSha256": null,
         "ambiguousResources": [],
         "presentResources": [
          "Chat/c1"
         ],
         "marks": {
          "startXmax": "805",
          "endXmax": "805",
          "inProgress": 0
         },
         "quiescent": true,
         "violated": false,
         "basis": "row versions (xmin) of public.Chat: every committed update writes a new xmin; 0 ambiguous rows"
        }
       ],
       "settleMs": 250,
       "lineage": {
        "observer": "postgres-snapshot-diff",
        "independence": "application-store"
       }
      }
     ]
    }
   ]
  },
  "catalog": {
   "schema": "scopehaven-catalog-identity/1",
   "sha256": "457e4ba9a890a4d1206ff347d1c87f8c184ce4055477ef51a6852f3de646a7aa",
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
      "schemas": [],
      "tables": []
     },
     "instanceId": "pg-snapshot-db"
    }
   ]
  },
  "durationMs": 603,
  "checksTotal": 2,
  "counts": {
   "pass": 1,
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
       "requestId": "466efcd1-6b57-4722-944b-f66473ee0899",
       "actorId": "bob",
       "method": "GET",
       "requestPathHash": "b4104b822236e8acba1cec3b8531cb785a5a11300e229b22306ba70151590fe2",
       "routeSegments": [
        {
         "exact": "77898838b3846c4a0f1b3baa360cf643abe99583a6c36243a1e8841abb336b4b",
         "keys": [
          "62ab6a58efc4eb90054ba30aa91a217bba6e2c8d184fedb3eb47cf0320b7a301"
         ]
        }
       ],
       "controlScope": {
        "cleanObject": true,
        "recordPredicates": [],
        "sentRoute": "044c90f30bd1fea6c9b937df9ec2167163533fc46ece643c3049d3c7c7f1d50d",
        "bodyKeys": "227cbb6c3a11032c42a89433c0f16b2ad3aa86ee950f27a1249f915579e696c7" // gitleaks:allow: a sha256 digest of the request body's key names that main's connector sealed into the run, not a credential
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
    "durationMs": 7,
    "evidenceDigest": "45ca3049f29b66f10f5798cfd31f11fa8819f88916e5bea2aec0515287897fd9",
    "decision": "pass"
   },
   {
    "id": "BOB-ALICE-CHAT",
    "title": "Bob cannot read alice's chat, and the read changes nothing",
    "category": "object-access",
    "severity": "high",
    "status": "inconclusive",
    "assertions": [
     {
      "name": "HTTP status matches contract",
      "status": "pass",
      "expected": "HTTP 403",
      "actual": "HTTP 403"
     },
     {
      "name": "Trusted backend observation available",
      "status": "pass",
      "expected": "Independent backend evidence required",
      "actual": "Authoritative observers decided every declared effect"
     },
     {
      "name": "Observed effect 1 (effect.none)",
      "status": "inconclusive",
      "expected": "No matching committed effect",
      "actual": "inconclusive: Every authoritative observer that can see this effect (pg-snapshot-db) covered the window and recorded no matching committed effect. Coverage basis: row versions (xmin) of public.Chat: every committed update writes a new xmin; 0 ambiguous rows. Custody: every observer that decided this keeps a record the application can write, so it cannot support a pass.",
      "custody": "subject-writable",
      "custodyReason": "subject-writable-custody",
      "custodyUpgrade": "No shipped observer held outside the application sees operation update, name Chat, resource Chat/c1. Decide it through the tool call or outbound send that carries it, if there is one, or accept this row as inconclusive."
     },
     {
      "name": "Actor identity established by required controls",
      "status": "inconclusive",
      "expected": "The actor's identity, and any allowed use this check depends on, are established in this run",
      "actual": "This actor's login was proven only on its identity route: no required allowed-use GET control on a protected route was bracketed around its checks, so a refusal cannot be told apart from a credential the protected routes reject"
     }
    ],
    "observed": {
     "httpStatus": 403,
     "complete": true,
     "jsonParsed": true,
     "predicates": [],
     "evidenceScope": "response-and-observers"
    },
    "summary": "A response predicate or an observed effect could not be decided.",
    "evidenceRequirement": "backend",
    "expected": "Configured response predicates and independent backend evidence.",
    "backendEvidence": "observed",
    "trace": [
     {
      "type": "http-observation",
      "label": "Retained response metadata; response content is not stored",
      "data": {
       "requestId": "92111885-7e6e-4faa-9c4e-826d06ac17da",
       "actorId": "bob",
       "method": "GET",
       "requestPathHash": "b6347c4f93855141f790997daec0e560f41ff1182db96a296276a4f5bc2b60a2",
       "routeSegments": [
        {
         "exact": "70f6deb5a85e76a6bbc5dec2f4ac8d7a88a1069d78c86a794a3215e256916573",
         "keys": [
          "0bd52838ea8306186b1ecdd0cb2f7d51d1e60228f4cfca566a2668f4694726d9",
          "41954b3757c0ea39be16e27dcc0696d5a141ceaf2a23c77dfb99fa62e7d477c4",
          "99a89a8f4183130745601e95994213a8a9946a5e39bf09c3ffc6239040d28191",
          "ec8d374d0d512251caa27b18d2a9f299c163a18334df108ce03ecfc872caeed6"
         ]
        },
        {
         "exact": "ce16d7e3477858ba7ec2a87641299fb3b19832e3f79c079a54502b55ae8c383d",
         "keys": [
          "c2b93a89bd919b4c45a92c6553cb932e359a3165fe78a336aca70e308a838522"
         ]
        },
        {
         "exact": "19f96e530e15173d755f3b99317462ea2346c6f6aa66576a0989dd23378bc2e8",
         "keys": [
          "2479785e2e76e170354735f8ba59a8cce3476446ec6b4dd3ab793767f5b5e717",
          "544bf9c3a2cff26b2a589dd6bf8c7b3891eaa4a71d774627be6dedc4f0cec812",
          "7ed0219d13993319740f2e91e8ae6b0ee946e589649a1665b783899bcb2180d0",
          "8d672a9328f5d5fa4d79777ea7a6b03357f91da557d86fddf19b8b638fdf3bdd",
          "bd4556f0e803e9cd3d323ef1d91f5d76904dcae193614ddf869b25e3ff256641",
          "e16a6fa31b291a53957056b645f20404dceea4fd1599df513ebe624c76d5c1e9",
          "f7f27b9ba7e998ede8cc9b69ab37688bf817d2660bf24fac791f08e5f9d30f9c"
         ]
        }
       ],
       "controlScope": {
        "cleanObject": false,
        "recordPredicates": [],
        "sentRoute": "7d7fd651c0bb8d40622bfed4e5b86edd984982b22539e953283ece4db4e0d580",
        "bodyKeys": null
       },
       "credentialMode": "bearer",
       "requestTimeoutMs": 3000,
       "httpStatus": 403,
       "responseComplete": true,
       "responseBytes": 21,
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
          "source": "sql-snapshot",
          "name": "Chat",
          "operation": "update",
          "resource": "Chat/c1"
         },
         "verdict": "inconclusive",
         "matched": 0,
         "custody": "subject-writable",
         "custodyReason": "subject-writable-custody",
         "custodyUpgrade": "No shipped observer held outside the application sees operation update, name Chat, resource Chat/c1. Decide it through the tool call or outbound send that carries it, if there is one, or accept this row as inconclusive."
        }
       ],
       "windows": [
        {
         "source": "sql-snapshot",
         "instanceId": "pg-snapshot-db",
         "scope": {
          "operations": [
           "insert",
           "update",
           "delete"
          ],
          "names": [
           "Chat"
          ],
          "actorAttribution": "none",
          "evidence": "authoritative"
         },
         "coverage": "net-only",
         "reason": "net-change-between-snapshots",
         "events": [],
         "exact": [
          {
           "name": "Chat",
           "method": "xmin",
           "auditSha256": null,
           "ambiguousResources": [],
           "presentResources": [
            "Chat/c1"
           ],
           "marks": {
            "startXmax": "800",
            "endXmax": "805",
            "inProgress": 0
           },
           "violated": false,
           "basis": "row versions (xmin) of public.Chat: every committed update writes a new xmin; 0 ambiguous rows"
          }
         ],
         "settleMs": 250,
         "lineage": {
          "observer": "postgres-snapshot-diff",
          "independence": "application-store"
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
      "Check BOB-ALICE-CHAT"
     ]
    },
    "durationMs": 276,
    "evidenceDigest": "f8f1d29d10247360239b899290e5d4c8cc773a06c149c01293784933ae7e0520",
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
     "between": [],
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
   "Postgres snapshot observers (db) read each declared heap table's row versions in one read-only snapshot per mark, with row-level security off (a role a policy would filter fails the window): an update of an existing row is exact (every committed update writes a new xmin), absence is claimed only about a named row seen at both marks (a prefix or table-wide selector is exact only on a window in which no transaction anywhere in the cluster completed or was in progress), partitions and inheritance children must be heap tables the parent scan reads (another session's temporary child or a partition being detached concurrently fails the window), each mark locks the tables (and their descendants) before its snapshot, so DDL cannot change what the scan reads on a table it locked, and a mark that reads a relation it holds no lock on fails; rows that cannot be identified across the marks (a replaced or rewritten table, a changed set of partitions, renamed or retyped columns, a key whose row version is new to it yet predates the start mark, as when key texts are relabelled or swapped, a duplicated key, a regressed xmax or a server restart) fail the window with no events, inserts and deletes are net-only, and a write transaction seen in progress at a window's end makes it partial. A write transaction that commits in the instant between the end mark's snapshot and its lock read reads as committed after the end mark. A standby, a view, a foreign table, another access method, an unlogged table (crash recovery empties it) or a key whose text is not fixed by its stored bytes (a type whose output function is not immutable and does not depend only on a pinned setting, such as an enum, a reg* type, aclitem, an array, range or composite; a virtual generated column; or a name that is not a column) fails the window; an output function declared immutable is trusted to be one.",
   "Observed effects are judged from the declared observers only. Traces and tool-call logs can show an effect happened; only an audit log, the application database or the request-path gate can show it did not, and a missing or presence-only observer leaves the effect unverifiable, never a pass.",
   "Custody: in a boundary check (any severity except control), an observed effect passes only when an observer that decided it keeps its record outside the application (the hold gate, an egress recorder or an SMTP sink). One decided only by records the application can write (its audit logs, its database, its traces or tool-call logs) reads inconclusive. Allowed-use controls keep their verdicts and carry custody as a tag only: a record the application can write may show an allowed action happened when it did not.",
   "Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: db 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
   "A credentialed actor's login counts only with positive evidence in the same run: a required GET control returning its declared identity, refused without a credential, with an invalid credential (a random look-alike of the actor's own, made fresh each run) and with each other actor's credential, and passing again with the actor's surface controls (its other required GET controls, on protected routes) at a probe point before the actor's first other check and after each of them, each probe in full. Identity is judged per check (actor-identity/5): a check rests on that identity route proof and on the two probe points around it. A point that did not pass withholds the checks it covers, ranked across both of a check's points, except that a required control is withheld only for a login-level reason (an identity probe that did not pass or did not finish at a point covering it, or a probe refused at any point), never because a surface probe failed for another reason; a check whose own two points passed keeps its status when another point fails. A probe refused with the actor's own credential at any point withholds every check of the actor, required and identity controls included, since a credential that flaps can be refused between two accepting points: a refused identity probe (401, 403, its declared sign-in redirect, or a complete 2xx that names another principal or none) reads bracket-not-passed, a refused surface probe (401, 403 or the declared redirect: the protected routes did not accept the credential the identity route accepted) reads surface-refused, and bracket-not-passed when both were refused. A surface probe that fails otherwise (a 500, a 404) leaves the checks its point covers not established. A withheld check is inconclusive; a boundary check whose refusal was observed while its identity or allowed use was not established is the distinct decision prohibition-observed-identity-unproven, never a pass. The gate reports identity-not-established for an actor whose route or any point did not hold, and a comparison never labels a row restored or fixed when its identity was not proven for it. A credentialed 401 on a boundary check is an authentication failure, not a refusal, unless the actor declares refusesWith401 and a surface control brackets its checks. A 403 or any other answer outside 2xx counts as a refusal only after the same actor's complete 2xx on a protected route (a surface control in its probe points); without one it is inconclusive. An outage strictly between the two probe points that cover a check is not detected. Evidence of credential loss on an actor's own main rows, rather than at a probe point, stays row-level: a credentialed 401 on a boundary check (unauthenticated-401), a redirect to the declared sign-in, or a required control answering a refusal status withholds or fails that row, and the gate fails, but a comparison may still credit other rows of that actor, and a change or a captured value that actor made still counts as attributed."
  ]
 }
};
