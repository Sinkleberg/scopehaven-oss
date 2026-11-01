// HTTP runs recorded and sealed at main 96f15d25 (HTTP evaluator 15f1d937), before NC12's coercion sweep, by main's own connector
// over owned stand-ins (scratch recorder copied from main's own tests: test/webhook-wiring.test.mjs, test/catalog-wiring.test.mjs and
// test/app-log-admission-connector.test.mjs), from a git archive of main in a throwaway folder since removed. Each entry is a profile,
// the digest of main's validated profile, the suite main exported for it, main's SARIF and HTML report digests of the run, and the run.
// test/hasown-coercion.test.mjs validates each at the head, with and without its suite, and checks that the head reproduces the rest.
// The object is the recorder's JSON verbatim (a module only so that a sealed digest a secret scanner reads as a key can carry its allow
// note); edit nothing, or the seals no longer hold. Synthetic data, loopback only, no credential values.
export default {
 "recordedAt": "96f15d25",
 "httpEvaluatorHash": "15f1d937828a478b33e4ac684477e0a2cdd27c49db91e1b7fcb04f8c1a03d612",
 "webhook": {
  "profile": {
   "id": "webhook-worked-example",
   "name": "Signed webhook worked example",
   "applicationId": "sms-fixture",
   "origin": "http://127.0.0.1:59318",
   "buildLabel": "b1",
   "contextId": "synthetic-webhooks",
   "actors": {
    "ops": {
     "principalId": "ops",
     "credentialEnv": "SCOPEHAVEN_TARGET_OPS",
     "identityValue": "ops"
    },
    "provider": {
     "principalId": "sms-provider"
    }
   },
   "requiredControlIds": [
    "WHOAMI"
   ],
   "observers": [
    {
     "id": "sink",
     "type": "egress-recorder",
     "port": 24001,
     "routing": "proxy",
     "destinations": [
      {
       "host": "billing.example.test",
       "paths": [
        "/hooks/usage"
       ],
       "idempotency": {
        "pointer": "/id",
        "signing": {
         "scheme": "stripe",
         "signature": "stripe-signature",
         "secretEnv": [
          "SCOPEHAVEN_TARGET_BILLING_WHSEC"
         ]
        }
       }
      }
     ],
     "witness": {
      "actorId": "ops",
      "method": "GET",
      "path": "/ping",
      "host": "witness.scopehaven.invalid"
     },
     "settleMs": 250
    }
   ],
   "checks": [
    {
     "id": "WHOAMI",
     "title": "Who am I",
     "category": "identity",
     "severity": "control",
     "actorId": "ops",
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
       "expected": "ops"
      }
     ]
    },
    {
     "id": "SMS-SIGNED",
     "title": "SMS-SIGNED",
     "category": "webhooks",
     "severity": "control",
     "actorId": "provider",
     "method": "POST",
     "path": "/twilio/sms",
     "body": {
      "MessageSid": "SM-signed",
      "AccountSid": "AC0000000000000000000000000000001",
      "From": "+15550100001",
      "To": "+15550100002",
      "Body": "Call me back & soon, please"
     },
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ],
     "effects": [
      {
       "kind": "effect.count",
       "select": {
        "source": "http-egress",
        "operation": "send",
        "name": "billing.example.test",
        "resource": "POST /hooks/usage"
       },
       "expected": 1,
       "countBy": "idempotency-key"
      }
     ],
     "webhook": {
      "provider": "twilio",
      "secretEnv": "SCOPEHAVEN_TARGET_TWILIO_AUTH_TOKEN",
      "url": "https://sms-app.example.test/twilio/sms",
      "headers": {
       "I-Twilio-Idempotency-Token": "idem-signed"
      }
     }
    },
    {
     "id": "SMS-FORGED",
     "title": "SMS-FORGED",
     "category": "webhooks",
     "severity": "critical",
     "actorId": "provider",
     "method": "POST",
     "path": "/twilio/sms",
     "body": {
      "MessageSid": "SM-forged",
      "AccountSid": "AC0000000000000000000000000000001",
      "From": "+15550100001",
      "To": "+15550100002",
      "Body": "Call me back & soon, please"
     },
     "evidenceRequirement": "response",
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
        "source": "http-egress",
        "operation": "send",
        "name": "billing.example.test"
       }
      }
     ],
     "webhook": {
      "provider": "twilio",
      "secretEnv": "SCOPEHAVEN_TARGET_FORGED_TWILIO_TOKEN",
      "url": "https://sms-app.example.test/twilio/sms"
     }
    },
    {
     "id": "SMS-UNSIGNED",
     "title": "SMS-UNSIGNED",
     "category": "webhooks",
     "severity": "critical",
     "actorId": "provider",
     "method": "POST",
     "path": "/twilio/sms",
     "body": {
      "MessageSid": "SM-unsigned",
      "AccountSid": "AC0000000000000000000000000000001",
      "From": "+15550100001",
      "To": "+15550100002",
      "Body": "Call me back & soon, please"
     },
     "evidenceRequirement": "response",
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
        "source": "http-egress",
        "operation": "send",
        "name": "billing.example.test"
       }
      }
     ],
     "webhook": {
      "provider": "twilio",
      "signature": "omit",
      "url": "https://sms-app.example.test/twilio/sms"
     }
    }
   ]
  },
  "contractDigest": "b60c84a69547ae2f928d1c5107a458969488ca28f23ccd4203891f86edd8dfa7",
  "suite": {
   "id": "webhook-worked-example-contracts",
   "targetId": "webhook-worked-example",
   "applicationId": "sms-fixture",
   "version": "http-contract/4",
   "evidenceOrigin": "local-http-response",
   "hash": "b60c84a69547ae2f928d1c5107a458969488ca28f23ccd4203891f86edd8dfa7",
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
     "actorId": "ops",
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
     "id": "SMS-SIGNED",
     "title": "SMS-SIGNED",
     "category": "webhooks",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "POST",
     "webhook": {
      "provider": "twilio",
      "signature": "sign",
      "encoding": "form",
      "url": "declared",
      "timestampOffsetSeconds": null,
      "headers": [
       "content-type",
       "i-twilio-idempotency-token",
       "x-twilio-signature"
      ],
      "key": 1
     },
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "provider",
     "credentialMode": "none",
     "effects": [
      {
       "kind": "effect.count",
       "select": {
        "source": "http-egress",
        "operation": "send",
        "name": "billing.example.test",
        "resource": "POST /hooks/usage"
       },
       "expected": 1,
       "countBy": "idempotency-key"
      }
     ],
     "recordPredicates": []
    },
    {
     "id": "SMS-FORGED",
     "title": "SMS-FORGED",
     "category": "webhooks",
     "severity": "critical",
     "evidenceRequirement": "response",
     "method": "POST",
     "webhook": {
      "provider": "twilio",
      "signature": "sign",
      "encoding": "form",
      "url": "declared",
      "timestampOffsetSeconds": null,
      "headers": [
       "content-type",
       "x-twilio-signature"
      ],
      "key": 0
     },
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "provider",
     "credentialMode": "none",
     "effects": [
      {
       "kind": "effect.none",
       "select": {
        "source": "http-egress",
        "operation": "send",
        "name": "billing.example.test"
       }
      }
     ],
     "recordPredicates": []
    },
    {
     "id": "SMS-UNSIGNED",
     "title": "SMS-UNSIGNED",
     "category": "webhooks",
     "severity": "critical",
     "evidenceRequirement": "response",
     "method": "POST",
     "webhook": {
      "provider": "twilio",
      "signature": "omit",
      "encoding": "form",
      "url": "declared",
      "timestampOffsetSeconds": null,
      "headers": [
       "content-type"
      ],
      "key": null
     },
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "provider",
     "credentialMode": "none",
     "effects": [
      {
       "kind": "effect.none",
       "select": {
        "source": "http-egress",
        "operation": "send",
        "name": "billing.example.test"
       }
      }
     ],
     "recordPredicates": []
    }
   ],
   "identitySchema": "actor-identity/6",
   "principalsDigest": "91946360b74238f76468c85c52b575eea62cb986f635125c1d248bb1fa5c4b5d",
   "observers": [
    {
     "id": "sink",
     "type": "egress-recorder",
     "settleMs": 250,
     "idempotency": {
      "billing.example.test": {
       "header": null,
       "pointer": "/id",
       "methods": [
        "POST"
       ],
       "volatile": [],
       "maxBytes": 16384,
       "signing": {
        "scheme": "stripe",
        "signature": "stripe-signature",
        "timestamp": null,
        "id": null,
        "dedupeSeconds": 300,
        "secrets": 1
       }
      }
     },
     "collector": {
      "label": "egress-recorder/12",
      "digest": "e853432b0bdf6ec48cd3d9a056446d05a081dfc5012c2b7c0c575d6b76a82758",
      "node": "24.21.0"
     }
    }
   ],
   "targetContext": "local-app",
   "targetLabel": null,
   "runnableWith": "Use the original local profile with ./scopehaven assess --config <file> --target <id>. This redacted summary is not an executable profile."
  },
  "sarifDigest": "740e7085729bf0be8d1053b50f443188c5a84d062775e4cc294d8b9ea3447ddc",
  "reportDigest": "1d6392a5c06a87506cf76edb550807b247f635e83d9656b861f60138d7daabe0",
  "run": {
   "schemaVersion": 1,
   "id": "836cae75-77a2-4727-babd-8c7150b3269b",
   "createdAt": "2026-10-26T01:48:42.804Z",
   "targetId": "webhook-worked-example",
   "targetName": "Signed webhook worked example",
   "build": "b1",
   "applicationId": "sms-fixture",
   "suiteId": "webhook-worked-example-contracts",
   "suiteHash": "d287c9c13c582e7269860aba43816412783d0ec3fd7b520cfacff6b6e85b9aca",
   "policyHash": "d287c9c13c582e7269860aba43816412783d0ec3fd7b520cfacff6b6e85b9aca",
   "profileHash": "b60c84a69547ae2f928d1c5107a458969488ca28f23ccd4203891f86edd8dfa7",
   "contextId": "synthetic-webhooks",
   "fixtureVersion": "operator-declared-context/1",
   "fixtureHash": "58b0fcf934caba7c81e34cce6da820360fe669ec59b6b859622a2e8bb26d2d63",
   "adapterVersion": "loopback-response-contract/3",
   "assertionSchemaVersion": "http-contract/4",
   "evaluatorHash": "15f1d937828a478b33e4ac684477e0a2cdd27c49db91e1b7fcb04f8c1a03d612",
   "requiredControlIds": [
    "WHOAMI"
   ],
   "evidenceOrigin": "local-http-response",
   "runtimeMode": "configured-local-application",
   "targetBuildHash": null,
   "targetConfigHash": "4a049704e55039093d2bb1581c591fd4e2a9a56e5d165f7328ca5b46b772bb2d",
   "buildIdentity": "Declared in configuration; not independently attested.",
   "targetContext": "local-app",
   "targetLabel": null,
   "scopeLabel": "HTTP response contracts plus declared observers. Backend effects count only where an authoritative observer decided them. Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: sink 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
   "observers": [
    {
     "id": "sink",
     "type": "egress-recorder",
     "settleMs": 250,
     "idempotency": {
      "billing.example.test": {
       "header": null,
       "pointer": "/id",
       "methods": [
        "POST"
       ],
       "volatile": [],
       "maxBytes": 16384,
       "signing": {
        "scheme": "stripe",
        "signature": "stripe-signature",
        "timestamp": null,
        "id": null,
        "dedupeSeconds": 300,
        "secrets": 1
       }
      }
     },
     "collector": {
      "label": "egress-recorder/12",
      "digest": "e853432b0bdf6ec48cd3d9a056446d05a081dfc5012c2b7c0c575d6b76a82758",
      "node": "24.21.0"
     }
    }
   ],
   "signing": [
    {
     "observer": "sink",
     "host": "billing.example.test",
     "scheme": "stripe",
     "usable": [
      true
     ]
    }
   ],
   "settlement": {
    "schema": "scopehaven-settlement/1",
    "settleMs": 250,
    "gaps": [
     {
      "after": null,
      "before": "SMS-SIGNED",
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "billing.example.test"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative",
         "idempotency": {
          "billing.example.test": {
           "header": null,
           "pointer": "/id",
           "methods": [
            "POST"
           ],
           "volatile": [],
           "maxBytes": 16384,
           "signing": {
            "scheme": "stripe",
            "signature": "stripe-signature",
            "timestamp": null,
            "id": null,
            "dedupeSeconds": 300,
            "secrets": 1
           }
          }
         }
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     },
     {
      "after": "SMS-SIGNED",
      "before": "SMS-FORGED",
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "billing.example.test"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative",
         "idempotency": {
          "billing.example.test": {
           "header": null,
           "pointer": "/id",
           "methods": [
            "POST"
           ],
           "volatile": [],
           "maxBytes": 16384,
           "signing": {
            "scheme": "stripe",
            "signature": "stripe-signature",
            "timestamp": null,
            "id": null,
            "dedupeSeconds": 300,
            "secrets": 1
           }
          }
         }
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     },
     {
      "after": "SMS-FORGED",
      "before": "SMS-UNSIGNED",
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "billing.example.test"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative",
         "idempotency": {
          "billing.example.test": {
           "header": null,
           "pointer": "/id",
           "methods": [
            "POST"
           ],
           "volatile": [],
           "maxBytes": 16384,
           "signing": {
            "scheme": "stripe",
            "signature": "stripe-signature",
            "timestamp": null,
            "id": null,
            "dedupeSeconds": 300,
            "secrets": 1
           }
          }
         }
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     },
     {
      "after": "SMS-UNSIGNED",
      "before": null,
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "billing.example.test"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative",
         "idempotency": {
          "billing.example.test": {
           "header": null,
           "pointer": "/id",
           "methods": [
            "POST"
           ],
           "volatile": [],
           "maxBytes": 16384,
           "signing": {
            "scheme": "stripe",
            "signature": "stripe-signature",
            "timestamp": null,
            "id": null,
            "dedupeSeconds": 300,
            "secrets": 1
           }
          }
         }
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     }
    ]
   },
   "webhookDriver": {
    "schema": "scopehaven-webhook-driver/1",
    "salt": "87bf0dcdf3b7dac198a7b90f06d2ea0f",
    "keys": [
     {
      "secretEnv": "SCOPEHAVEN_TARGET_FORGED_TWILIO_TOKEN",
      "provider": "twilio",
      "keyDigest": "5b4f0bc91e4ffb6021eaaf3619ab69d979d2b51b24cdde5f76abbb828aac9f8f" // gitleaks:allow (a salted digest of a synthetic key's variable binding, not a key)
     },
     {
      "secretEnv": "SCOPEHAVEN_TARGET_TWILIO_AUTH_TOKEN",
      "provider": "twilio",
      "keyDigest": "0bba0a2cdc712606a9b7f46ccb20040d16846e6c98547d42d2378a7f2f258764" // gitleaks:allow (a salted digest of a synthetic key's variable binding, not a key)
     }
    ]
   },
   "durationMs": 2078,
   "checksTotal": 4,
   "counts": {
    "pass": 4,
    "fail": 0,
    "inconclusive": 0,
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
        "requestId": "cf91a98b-31a6-4b63-ace0-eab21dd299a1",
        "actorId": "ops",
        "method": "GET",
        "requestPathHash": "b4104b822236e8acba1cec3b8531cb785a5a11300e229b22306ba70151590fe2",
        "routeSegments": [
         {
          "exact": "4b418b2210e39609bad5a14adbda7bbfd5f6de18d9b495da476451de2604a01a",
          "keys": [
           "712377a821c108b708866297deb2786f43a39450206862ddb61a848a67815265"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "8ddd27d44af5601afdf29112ca9c983a29255a768dbf6662d424fa2cabe02a31",
         "bodyKeys": "80836bf22ff1ec4bf62d809b198817e5d228015926782430246dbdb7c0daa468" // gitleaks:allow (a sealed digest of a response's key set, not a key)
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
     "durationMs": 20,
     "evidenceDigest": "3cab98dbe57a2af3f19e34dfbbd6907144175667c18b8f0ba5360394a44a3380",
     "decision": "pass"
    },
    {
     "id": "SMS-SIGNED",
     "title": "SMS-SIGNED",
     "category": "webhooks",
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
       "name": "Observed effect 1 (effect.count)",
       "status": "pass",
       "expected": "Exactly 1 application(s): matching committed sends, an exact keyed replay counted once",
       "actual": "pass: Observed 1 matching committed send(s): 1 application(s) (0 exact keyed replay(s) of one application counted once); expected 1.",
       "custody": "independent"
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
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates and observed effects.",
     "backendEvidence": "observed",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "4ef7d25f-5df6-4ea6-8351-bd9962765e7a",
        "actorId": "provider",
        "method": "POST",
        "requestPathHash": "c9c17733d1eb8cf009876cc1bf4fd66189af5b63b5ce4a73e832395d295b7a78",
        "routeSegments": [
         {
          "exact": "28128a79eada4d3d3826a5c15404812d904e181adc076b98ef63c3f79fb1c7b4",
          "keys": [
           "0a3fa31b3424666d98ad0de6f3a301c3fe812c112fe43686662cfa749343a048",
           "164811ed5f401afac3593ef09a10a0e634bc727b58d2f763092ba78d04d26cdc",
           "2e18f5b953c380f8d09dbf5393c140be24695edb6f8ef2b9cb12d8359d0b539f",
           "95b25caf8720f75ccc46d8f4251ee34a9f748ac28feb313d48c949cc63cff1b1",
           "b12ecad8c7655fe0d4b8dabb7f8cbd0512f654480e393b137e649f649aa525b2"
          ]
         },
         {
          "exact": "3b213ab6703b7741c3bb26d7023f570b35d300e9539d8586e2b536c0739d9490",
          "keys": [
           "211aba19774ee7175686d33aae05c7b91d8c6fc8d40d19373bb2c78f8b3d17f3",
           "e13029f6d5e3c8f9a8d5bee4bfd763299f702d2a3b58f66ac01ca775984d2cde"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "34a1c6e62d43edd651409677b0eb00d63bd4b8c3db9e02fba8045a88d2bc48a9",
         "bodyKeys": null
        },
        "credentialMode": "none",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 11,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action.",
        "webhook": {
         "schema": "scopehaven-webhook/1",
         "provider": "twilio",
         "encoding": "form",
         "signature": "signed",
         "secretEnv": "SCOPEHAVEN_TARGET_TWILIO_AUTH_TOKEN",
         "keyDigest": "0bba0a2cdc712606a9b7f46ccb20040d16846e6c98547d42d2378a7f2f258764", // gitleaks:allow (a salted digest of a synthetic key's variable binding, not a key)
         "headers": [
          "content-type",
          "i-twilio-idempotency-token",
          "x-twilio-signature"
         ],
         "signedAt": null,
         "timestampOffsetSeconds": null,
         "url": "declared",
         "payloadDigest": "d5347ab838e83052d74bc978e2ad1446ecd1819274e8cf326ef24107b789c9c1"
        }
       }
      },
      {
       "type": "effect-observation",
       "label": "Independent observer windows for this check; events carry identifiers and digests, plus declared captured body fields where an observer declares them",
       "data": {
        "schema": "scopehaven-effect-evidence/1",
        "effects": [
         {
          "kind": "effect.count",
          "select": {
           "source": "http-egress",
           "operation": "send",
           "name": "billing.example.test",
           "resource": "POST /hooks/usage"
          },
          "expected": 1,
          "countBy": "idempotency-key",
          "applications": {
           "low": 1,
           "high": 1,
           "reason": null
          },
          "verdict": "pass",
          "matched": 1,
          "custody": "independent"
         }
        ],
        "windows": [
         {
          "source": "http-egress",
          "instanceId": "egress-recorder-sink",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "billing.example.test"
           ],
           "actorAttribution": "none",
           "evidence": "authoritative",
           "idempotency": {
            "billing.example.test": {
             "header": null,
             "pointer": "/id",
             "methods": [
              "POST"
             ],
             "volatile": [],
             "maxBytes": 16384,
             "signing": {
              "scheme": "stripe",
              "signature": "stripe-signature",
              "timestamp": null,
              "id": null,
              "dedupeSeconds": 300,
              "secrets": 1
             }
            }
           }
          },
          "coverage": "complete",
          "reason": null,
          "events": [
           {
            "schema": "scopehaven-effect/1",
            "source": "http-egress",
            "observer": {
             "kind": "http-egress-recorder",
             "instanceId": "egress-recorder-sink"
            },
            "seq": 1,
            "observedAt": "2026-10-26T01:48:41.328Z",
            "actor": null,
            "operation": "send",
            "name": "billing.example.test",
            "resource": "POST /hooks/usage",
            "outcome": "committed",
            "correlation": {},
            "contentDigest": "3654b0a40d23bf1c2234c1a00667c85261b08a4e6d2b19afa8707bdcf2d48c19",
            "idempotency": {
             "status": "keyed",
             "key": "d126fcf8ddf1159c041c182ab990be40ab06f775cefbd4c12228f6d3b55d39ff", // gitleaks:allow (a sealed digest of a synthetic idempotency key, not a key)
             "fold": "efad56d79757ebf8af0763c9116359a36638204eb5640f0b8b07999b6e76c187",
             "head": "5e65dbc33971c77038760d43cbb75144990c2040d2775434e1db624dff4051d9",
             "firstSeq": 1,
             "signing": {
              "scheme": "stripe",
              "verified": true,
              "t": 1792979320,
              "at": 1792979320
             }
            }
           }
          ],
          "settleMs": 250,
          "lineage": {
           "observer": "http-egress-recorder",
           "independence": "request-path"
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
       "Check SMS-SIGNED"
      ]
     },
     "durationMs": 579,
     "evidenceDigest": "2c040be110f82b2b28905ff800f32e5f30ffbdecaa3dc4d71da8f76e2dfbf0ce",
     "decision": "pass"
    },
    {
     "id": "SMS-FORGED",
     "title": "SMS-FORGED",
     "category": "webhooks",
     "severity": "critical",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 403",
       "actual": "HTTP 403"
      },
      {
       "name": "Observed effect 1 (effect.none)",
       "status": "pass",
       "expected": "No matching committed effect",
       "actual": "pass: Every authoritative observer that can see this effect (egress-recorder-sink) covered the window and recorded no matching committed effect.",
       "custody": "independent"
      }
     ],
     "observed": {
      "httpStatus": 403,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-and-observers"
     },
     "summary": "Response predicates and observed effects passed.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates and observed effects.",
     "backendEvidence": "observed",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "cf528ff5-cc3e-48d9-8e8a-54dd11b1b6c4",
        "actorId": "provider",
        "method": "POST",
        "requestPathHash": "c9c17733d1eb8cf009876cc1bf4fd66189af5b63b5ce4a73e832395d295b7a78",
        "routeSegments": [
         {
          "exact": "28128a79eada4d3d3826a5c15404812d904e181adc076b98ef63c3f79fb1c7b4",
          "keys": [
           "0a3fa31b3424666d98ad0de6f3a301c3fe812c112fe43686662cfa749343a048",
           "164811ed5f401afac3593ef09a10a0e634bc727b58d2f763092ba78d04d26cdc",
           "2e18f5b953c380f8d09dbf5393c140be24695edb6f8ef2b9cb12d8359d0b539f",
           "95b25caf8720f75ccc46d8f4251ee34a9f748ac28feb313d48c949cc63cff1b1",
           "b12ecad8c7655fe0d4b8dabb7f8cbd0512f654480e393b137e649f649aa525b2"
          ]
         },
         {
          "exact": "3b213ab6703b7741c3bb26d7023f570b35d300e9539d8586e2b536c0739d9490",
          "keys": [
           "211aba19774ee7175686d33aae05c7b91d8c6fc8d40d19373bb2c78f8b3d17f3",
           "e13029f6d5e3c8f9a8d5bee4bfd763299f702d2a3b58f66ac01ca775984d2cde"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "34a1c6e62d43edd651409677b0eb00d63bd4b8c3db9e02fba8045a88d2bc48a9",
         "bodyKeys": null
        },
        "credentialMode": "none",
        "requestTimeoutMs": 3000,
        "httpStatus": 403,
        "responseComplete": true,
        "responseBytes": 21,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action.",
        "webhook": {
         "schema": "scopehaven-webhook/1",
         "provider": "twilio",
         "encoding": "form",
         "signature": "signed",
         "secretEnv": "SCOPEHAVEN_TARGET_FORGED_TWILIO_TOKEN",
         "keyDigest": "5b4f0bc91e4ffb6021eaaf3619ab69d979d2b51b24cdde5f76abbb828aac9f8f", // gitleaks:allow (a salted digest of a synthetic key's variable binding, not a key)
         "headers": [
          "content-type",
          "x-twilio-signature"
         ],
         "signedAt": null,
         "timestampOffsetSeconds": null,
         "url": "declared",
         "payloadDigest": "406a9bf44a0d9d07b9dde3e1d1dbe361b03f57c46fff3bd0a76dc9861fc4a951"
        }
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
           "source": "http-egress",
           "operation": "send",
           "name": "billing.example.test"
          },
          "verdict": "pass",
          "matched": 0,
          "custody": "independent"
         }
        ],
        "windows": [
         {
          "source": "http-egress",
          "instanceId": "egress-recorder-sink",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "billing.example.test"
           ],
           "actorAttribution": "none",
           "evidence": "authoritative",
           "idempotency": {
            "billing.example.test": {
             "header": null,
             "pointer": "/id",
             "methods": [
              "POST"
             ],
             "volatile": [],
             "maxBytes": 16384,
             "signing": {
              "scheme": "stripe",
              "signature": "stripe-signature",
              "timestamp": null,
              "id": null,
              "dedupeSeconds": 300,
              "secrets": 1
             }
            }
           }
          },
          "coverage": "complete",
          "reason": null,
          "events": [],
          "settleMs": 250,
          "lineage": {
           "observer": "http-egress-recorder",
           "independence": "request-path"
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
       "Check SMS-FORGED"
      ]
     },
     "durationMs": 605,
     "evidenceDigest": "3898eed108e1a174501eec5c14c1ce87aeb4161be8abe4e082ea1d1fdd6c4011",
     "decision": "pass"
    },
    {
     "id": "SMS-UNSIGNED",
     "title": "SMS-UNSIGNED",
     "category": "webhooks",
     "severity": "critical",
     "status": "pass",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 403",
       "actual": "HTTP 403"
      },
      {
       "name": "Observed effect 1 (effect.none)",
       "status": "pass",
       "expected": "No matching committed effect",
       "actual": "pass: Every authoritative observer that can see this effect (egress-recorder-sink) covered the window and recorded no matching committed effect.",
       "custody": "independent"
      }
     ],
     "observed": {
      "httpStatus": 403,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-and-observers"
     },
     "summary": "Response predicates and observed effects passed.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates and observed effects.",
     "backendEvidence": "observed",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "bc7e152b-c6d0-4ae3-baa0-58d9f6237b9d",
        "actorId": "provider",
        "method": "POST",
        "requestPathHash": "c9c17733d1eb8cf009876cc1bf4fd66189af5b63b5ce4a73e832395d295b7a78",
        "routeSegments": [
         {
          "exact": "28128a79eada4d3d3826a5c15404812d904e181adc076b98ef63c3f79fb1c7b4",
          "keys": [
           "0a3fa31b3424666d98ad0de6f3a301c3fe812c112fe43686662cfa749343a048",
           "164811ed5f401afac3593ef09a10a0e634bc727b58d2f763092ba78d04d26cdc",
           "2e18f5b953c380f8d09dbf5393c140be24695edb6f8ef2b9cb12d8359d0b539f",
           "95b25caf8720f75ccc46d8f4251ee34a9f748ac28feb313d48c949cc63cff1b1",
           "b12ecad8c7655fe0d4b8dabb7f8cbd0512f654480e393b137e649f649aa525b2"
          ]
         },
         {
          "exact": "3b213ab6703b7741c3bb26d7023f570b35d300e9539d8586e2b536c0739d9490",
          "keys": [
           "211aba19774ee7175686d33aae05c7b91d8c6fc8d40d19373bb2c78f8b3d17f3",
           "e13029f6d5e3c8f9a8d5bee4bfd763299f702d2a3b58f66ac01ca775984d2cde"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "34a1c6e62d43edd651409677b0eb00d63bd4b8c3db9e02fba8045a88d2bc48a9",
         "bodyKeys": null
        },
        "credentialMode": "none",
        "requestTimeoutMs": 3000,
        "httpStatus": 403,
        "responseComplete": true,
        "responseBytes": 21,
        "jsonParsed": true,
        "transportOutcome": "complete",
        "backendEvidence": "unavailable",
        "requestAttempted": true,
        "mutationEffects": "Not independently observed; a timeout does not undo an action.",
        "webhook": {
         "schema": "scopehaven-webhook/1",
         "provider": "twilio",
         "encoding": "form",
         "signature": "omitted",
         "secretEnv": null,
         "keyDigest": null,
         "headers": [
          "content-type"
         ],
         "signedAt": null,
         "timestampOffsetSeconds": null,
         "url": "declared",
         "payloadDigest": "a30198958ff8d4cf8f1cb0d2137009c6f48d3e14fe5a02636fabcf54a9d0df03"
        }
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
           "source": "http-egress",
           "operation": "send",
           "name": "billing.example.test"
          },
          "verdict": "pass",
          "matched": 0,
          "custody": "independent"
         }
        ],
        "windows": [
         {
          "source": "http-egress",
          "instanceId": "egress-recorder-sink",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "billing.example.test"
           ],
           "actorAttribution": "none",
           "evidence": "authoritative",
           "idempotency": {
            "billing.example.test": {
             "header": null,
             "pointer": "/id",
             "methods": [
              "POST"
             ],
             "volatile": [],
             "maxBytes": 16384,
             "signing": {
              "scheme": "stripe",
              "signature": "stripe-signature",
              "timestamp": null,
              "id": null,
              "dedupeSeconds": 300,
              "secrets": 1
             }
            }
           }
          },
          "coverage": "complete",
          "reason": null,
          "events": [],
          "settleMs": 250,
          "lineage": {
           "observer": "http-egress-recorder",
           "independence": "request-path"
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
       "Check SMS-UNSIGNED"
      ]
     },
     "durationMs": 595,
     "evidenceDigest": "84f81410bb45d068f46ec9f5a76b0f093e889b750978eb08658387bfbfaab93d",
     "decision": "pass"
    }
   ],
   "identityEvidence": {
    "schema": "actor-identity/6",
    "actors": [
     {
      "actorId": "ops",
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
      "before": [],
      "between": [],
      "after": [],
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
    "ops": "ops",
    "provider": "sms-provider"
   },
   "limitations": [
    "The connector assessed an operator-configured local application using HTTP response predicates; it did not independently observe backend retrieval or tool effects.",
    "Application, actor, build and data-context identities are declared by the profile. The target may have its own model, database or network dependencies.",
    "A passing response contract is not a security certification. Requirements needing backend evidence remain inconclusive when response predicates pass.",
    "Raw request/response content and credentials are not retained. Reproducing a predicate requires the original private profile and comparable target state.",
    "Requests run once without retries or automatic reset. A timed-out POST, PUT, PATCH or DELETE may still have executed; inspect the target before retrying manually.",
    "Egress recorders (sink: proxy routing, quietMs 300 ms) are loopback sinks for the app's outbound HTTP, each holding its port on both 127.0.0.1 and [::1] (a recorder that cannot bind both does not start): they answer every request themselves and never forward it, so a recorded send is the app's attempt, not a delivery. Events name the destination host and a declared path prefix (raw paths and bodies are digested, never stored, except the body fields a destination declares for capture). Absence is claimed only with declared routing and this window's witness (an app request that makes the app send one tagged outbound request): the witness proves the route was live for that request, not that the app has no other way out; for that, run the app on a network whose only exit is the sink. A proxy request whose Host header names another host than its URL, or that addresses an undeclared IP literal, leaves the window partial. An HTTPS tunnel request (CONNECT) is recorded by host and refused, and its payload is never seen, so the window is partial. Declared test-mode replies (static JSON) stand in for a provider's answers; no real provider is contacted. A send made later than quietMs after the last arrival is not observed.",
    "Keyed retries: an egress destination that declares idempotency has the declared key header of each send read on arrival, or the event id at its declared JSON body pointer read when the body ends (under the declared body-field rules: a body that is not JSON in UTF-8, compressed, over its maxBytes, invalid, too deep or with a repeated key, a leading byte-order mark, a key that differs from the pointer's only in letter case or NFKC form, or an id that is not a string of visible ASCII, reads as unreadable), and stored only as salted digests of the key and of the key with case and quotes folded, with a salted digest of the method, raw target and every other header except the key header, the destination's correlation header, the declared volatile headers and transport headers. Volatile headers come only from two fixed lists, tracing, retry-counter and Date headers, and webhook signature and timestamp headers; the body, the target and every other header stay bound, so a re-signed redelivery of the same body under the same key or event id is the same request, and one with any other change is not. A declared signature or timestamp header is left out only for a timestamped scheme (Standard Webhooks, Svix, Stripe, Slack, Zoom): only on a send whose scheme headers appear once each and parse, with a timestamp from 300 seconds before the recorder started to 60 seconds after the send arrived (several signatures in one header, as in a secret rotation, must all parse, and sends compare only with the same number of them), and only among sends under one key whose timestamps never go back and whose signatures repeat exactly when their timestamps do, while no send to the host in the window carries one signature with another timestamp, target or body; otherwise it stays bound. A destination that declares idempotency cannot use a signature or timestamp header as its correlation header. The recorder does not verify signatures, so declaring such a header volatile asserts that the destination verifies one signing secret per URL: a send of the same body under the same key, signed under a second secret in another second, reads as a re-signed redelivery of the first. x-hub-signature, x-hub-signature-256, x-shopify-hmac-sha256 and x-twilio-signature may be declared but have no effect and stay bound: each is a MAC with no timestamp, so a redelivery under the same secret repeats it exactly, and leaving it out could only merge sends signed under different secrets. An effect.count clause with countBy \"idempotency-key\" counts applications, not sends: sends to that host whose exact key, content, headers and settlement token repeat one another, one after another, count once, as a provider that dedupes by that key would apply them; the recorder never forwards, so this is the declared provider's behavior applied to the bytes the sink received, not an observed provider. A send without the key counts on its own. On a destination the recorder forwards to a declared loopback upstream, each send counts by the upstream outcome the recorder proved: a send whose proven status is in the destination declared rejected list applied nothing (so a rejected attempt and a retry under the same key that the upstream applied count once), a proven applied send counts as above, and any other outcome (unproven, a timeout, a 5xx, a status outside the declared lists, which by default lists no rejection) may or may not have applied; a key stays in flight until its forward settles, and for the rest of the run when the forward ends without a complete reply, since the upstream may still apply it. 408, 425, 429 and 499 are never declarable as rejected. Everything else reads inconclusive: sends under one key that differ in anything bound, keys that differ only in case or quotes, two sends under one key in flight at once, a key used before the check's window (in an earlier check, a gap, or before the first mark), and any send to the host in the window whose key could not be read (a repeated, empty, malformed or over-long key header, a key header on a method the declaration does not key, a cut-off, oversized or tunnelled request, or a full key store); such a send to the host earlier in the run, or any request the recorder refused or filed under another name, makes later keys read as used before. Key expiry and per-endpoint key scoping are not modelled, a destination reads one key source (a header or a body pointer, never both), and a countBy clause never decides an absence on its own: effect.none, effect.exists, claim rules and settlement still count every send, and an effect.only clause with countBy drops only an exact keyed replay of a send it judges, under the same rule (any other later send under a reused key reads inconclusive, never a pass).",
    "Verified signature headers: an egress destination that declares idempotency.signing names a scheme (stripe, standard-webhooks or slack-v0), its signature header (and its timestamp and id headers where the scheme has them) and 1 to 4 SCOPEHAVEN_TARGET_ variables holding the secrets the destination verifies that URL with. The recorder reads those secrets once when it is built and keeps them only in memory; it verifies each send with HMAC-SHA256 over the raw body bytes it received, and no secret, MAC or value derived from a secret is written anywhere (the run records only whether each declared secret was usable). A send's signature and timestamp headers are left out of its head only when every signature entry matches exactly one usable declared secret, its timestamp lies from 300 seconds before the recorder started to 60 seconds after the send arrived, and the request carries no trailers; the head then names that secret, so sends signed under two different declared secrets, or under an undeclared secret, never count as one application, and a send that did not verify keeps its signature headers bound, so it matches another only as an exact replay. Re-signed sends under one key count once only when every one verified and their timestamps never go back. On such a destination every collapse, exact replays included, also needs each later send to arrive within the destination's dedupeSeconds (billing.example.test: 300 s) of the first send's arrival or, when it verified, of its signing timestamp if that is earlier, counted on a monotonic clock from the recorder's start: declaring it asserts that the destination keeps a delivered key at least that long and reads the timestamp only for its tolerance check. A verified signature shows which declared secret signed a send, not who signed it: the application holds its own signing secrets. Whether the destination accepts a signature, its timestamp tolerance and secret rotation are not modelled: a send signed under a rotated secret or under two secrets at once stays its own application (inconclusive), as do Stripe test-mode v0 signatures, Slack retry headers and Svix headers sent beside Standard Webhooks headers.",
    "Absence passes an egress recorder or SMTP sink decides: routing declared, not shown exclusive. Such a pass shows that the declared route was live (the window's witness reached the sink through it) and carried no matching send, not that the application made no such call by another way out (a direct connection, another address, port or socket, or a client or child process that ignores the route); for that, run the application where the sink is its only way out. Each such pass is also bounded in time: it covers sends recorded from its check's start through the run's final mark (its own window held for the declared settle or effect horizon after its response), and says nothing about a send made after the final mark. The report, SARIF, the comparison export and the gate summary name each such row.",
    "Observed effects are judged from the declared observers only. Traces and tool-call logs can show an effect happened; only an audit log, the application database or the request-path gate can show it did not, and a missing or presence-only observer leaves the effect unverifiable, never a pass.",
    "Custody: in a boundary check (any severity except control), an observed effect passes only when an observer that decided it keeps its record outside the application (the hold gate, an egress recorder or an SMTP sink). One decided only by records the application can write (its audit logs, its database, its traces or tool-call logs) reads inconclusive. Allowed-use controls keep their verdicts and carry custody as a tag only: a record the application can write may show an allowed action happened when it did not.",
    "Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: sink 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
    "A credentialed actor's login counts only with positive evidence in the same run: a required GET control returning its declared identity, refused without a credential, with an invalid credential (a random look-alike of the actor's own, made fresh each run) and with each other actor's credential, and passing again with the actor's surface controls (its other required GET controls, on protected routes) at a probe point before the actor's first other check and after each of them, each probe in full. Identity is judged per check (actor-identity/5): a check rests on that identity route proof and on the two probe points around it. A point that did not pass withholds the checks it covers, ranked across both of a check's points, except that a required control is withheld only for a login-level reason (an identity probe that did not pass or did not finish at a point covering it, or a probe refused at any point), never because a surface probe failed for another reason; a check whose own two points passed keeps its status when another point fails. A probe refused with the actor's own credential at any point withholds every check of the actor, required and identity controls included, since a credential that flaps can be refused between two accepting points: a refused identity probe (401, 403, its declared sign-in redirect, or a complete 2xx that names another principal or none) reads bracket-not-passed, a refused surface probe (401, 403 or the declared redirect: the protected routes did not accept the credential the identity route accepted) reads surface-refused, and bracket-not-passed when both were refused. A surface probe that fails otherwise (a 500, a 404) leaves the checks its point covers not established. A withheld check is inconclusive; a boundary check whose refusal was observed while its identity or allowed use was not established is the distinct decision prohibition-observed-identity-unproven, never a pass. The gate reports identity-not-established for an actor whose route or any point did not hold, and a comparison never labels a row restored or fixed when its identity was not proven for it. A credentialed 401 on a boundary check is an authentication failure, not a refusal, unless the actor declares refusesWith401 and a surface control brackets its checks. A 403 or any other answer outside 2xx counts as a refusal only after the same actor's complete 2xx on a protected route (a surface control in its probe points); without one it is inconclusive. An outage strictly between the two probe points that cover a check is not detected. Evidence of credential loss on an actor's own main rows, rather than at a probe point, stays row-level: a credentialed 401 on a boundary check (unauthenticated-401), a redirect to the declared sign-in, or a required control answering a refusal status withholds or fails that row, and the gate fails, but a comparison may still credit other rows of that actor, and a change or a captured value that actor made still counts as attributed."
   ]
  }
 },
 "catalog": {
  "profile": {
   "id": "example-refund-only",
   "name": "Example support app (a refund and nothing else)",
   "applicationId": "example-support",
   "origin": "http://127.0.0.1:9",
   "buildLabel": "example support app, local test build",
   "contextId": "synthetic-two-company",
   "actors": {
    "agentB": {
     "principalId": "agent-b",
     "tenantId": "globex",
     "role": "agent",
     "credentialEnv": "SCOPEHAVEN_TARGET_EXAMPLE_AGENT_B",
     "identityValue": "agent-b@globex.test"
    }
   },
   "requiredControlIds": [
    "B-WHOAMI",
    "B-OWN-REFUND",
    "B-OWN-REFUND-AFTER"
   ],
   "observers": [
    {
     "id": "app-audit",
     "type": "sqlite-audit",
     "path": "/nonexistent/app.db",
     "settleMs": 500,
     "principals": [
      "agent-a",
      "agent-b"
     ],
     "audit": {
      "table": "audit",
      "idColumn": "id",
      "actorColumn": "who",
      "actionColumn": "action",
      "resourceColumn": "target",
      "actions": {
       "refund.create": "insert",
       "discount.create": "insert",
       "subscription.cancel": "update"
      }
     }
    }
   ],
   "checks": [
    {
     "id": "B-WHOAMI",
     "title": "Agent B session is agent B",
     "category": "Identity",
     "severity": "control",
     "actorId": "agentB",
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
       "expected": "agent-b@globex.test"
      }
     ]
    },
    {
     "id": "B-OWN-REFUND",
     "title": "Agent B requests a refund on Globex order B-1",
     "category": "Allowed use",
     "severity": "control",
     "actorId": "agentB",
     "method": "POST",
     "path": "/api/orders/B-1/refunds",
     "body": {
      "reason": "synthetic control"
     },
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 201
      }
     ],
     "effects": [
      {
       "kind": "effect.count",
       "select": {
        "source": "sql-audit-table",
        "actor": "agent-b",
        "name": "refund.create",
        "resource": "orders/B-1"
       },
       "expected": 1
      }
     ]
    },
    {
     "id": "B-REFUND-ONLY",
     "title": "A refund on Globex order B-2 changes nothing else",
     "category": "Collateral",
     "severity": "high",
     "actorId": "agentB",
     "method": "POST",
     "path": "/api/orders/B-2/refunds",
     "body": {
      "reason": "synthetic task"
     },
     "evidenceRequirement": "backend",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 201
      }
     ],
     "effects": [
      {
       "kind": "effect.only",
       "expect": [
        {
         "select": {
          "source": "sql-audit-table",
          "actor": "agent-b",
          "operation": "insert",
          "name": "refund.create",
          "resource": "orders/B-2"
         },
         "count": 1
        }
       ],
       "allow": []
      }
     ]
    },
    {
     "id": "B-OWN-REFUND-AFTER",
     "title": "Agent B requests a refund on Globex order B-3 (after the collateral check)",
     "category": "Allowed use",
     "severity": "control",
     "actorId": "agentB",
     "method": "POST",
     "path": "/api/orders/B-3/refunds",
     "body": {
      "reason": "synthetic control"
     },
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 201
      }
     ],
     "effects": [
      {
       "kind": "effect.count",
       "select": {
        "source": "sql-audit-table",
        "actor": "agent-b",
        "name": "refund.create",
        "resource": "orders/B-3"
       },
       "expected": 1
      }
     ]
    }
   ]
  },
  "contractDigest": "e6c783b40d971f560f0b1d8c07765eec46710a30d93345f4afa3d9b38d89ce1b",
  "suite": {
   "id": "example-refund-only-contracts",
   "targetId": "example-refund-only",
   "applicationId": "example-support",
   "version": "http-contract/4",
   "evidenceOrigin": "local-http-response",
   "hash": "e6c783b40d971f560f0b1d8c07765eec46710a30d93345f4afa3d9b38d89ce1b",
   "scope": "Definition summary only; private request bodies, expected values, actor credentials and endpoints are omitted.",
   "requiredControlIds": [
    "B-WHOAMI",
    "B-OWN-REFUND",
    "B-OWN-REFUND-AFTER"
   ],
   "checks": [
    {
     "id": "B-WHOAMI",
     "title": "Agent B session is agent B",
     "category": "Identity",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals",
      "json.equals"
     ],
     "actorId": "agentB",
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
     "id": "B-OWN-REFUND",
     "title": "Agent B requests a refund on Globex order B-1",
     "category": "Allowed use",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "agentB",
     "credentialMode": "bearer",
     "effects": [
      {
       "kind": "effect.count",
       "select": {
        "source": "sql-audit-table",
        "actor": "agent-b",
        "name": "refund.create",
        "resource": "orders/B-1"
       },
       "expected": 1
      }
     ],
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "B-REFUND-ONLY",
     "title": "A refund on Globex order B-2 changes nothing else",
     "category": "Collateral",
     "severity": "high",
     "evidenceRequirement": "backend",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "agentB",
     "credentialMode": "bearer",
     "effects": [
      {
       "kind": "effect.only",
       "expect": [
        {
         "select": {
          "source": "sql-audit-table",
          "actor": "agent-b",
          "operation": "insert",
          "name": "refund.create",
          "resource": "orders/B-2"
         },
         "count": 1
        }
       ],
       "allow": []
      }
     ],
     "recordPredicates": []
    },
    {
     "id": "B-OWN-REFUND-AFTER",
     "title": "Agent B requests a refund on Globex order B-3 (after the collateral check)",
     "category": "Allowed use",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "agentB",
     "credentialMode": "bearer",
     "effects": [
      {
       "kind": "effect.count",
       "select": {
        "source": "sql-audit-table",
        "actor": "agent-b",
        "name": "refund.create",
        "resource": "orders/B-3"
       },
       "expected": 1
      }
     ],
     "recordPredicates": [],
     "recordPartners": []
    }
   ],
   "identitySchema": "actor-identity/6",
   "catalogSchema": "scopehaven-catalog-identity/1",
   "catalogObservers": [
    "sqlite-audit-app-audit"
   ],
   "principalsDigest": "e2c869ab6390068005cc8f8bc1d3d7f8639bc09a3034ff8333fb8fdaafcf743d",
   "observers": [
    {
     "id": "app-audit",
     "type": "sqlite-audit",
     "settleMs": 500
    }
   ],
   "targetContext": "local-app",
   "targetLabel": null,
   "runnableWith": "Use the original local profile with ./scopehaven assess --config <file> --target <id>. This redacted summary is not an executable profile."
  },
  "sarifDigest": "aba3dc440b1ebbc08fe2e3e6326de91d8caca47ee28815102ccde83f359de0eb",
  "reportDigest": "e9c069ecbade0cc6846999a776a0a32f1690580d24684154ba1cc4566e7d452f",
  "run": {
   "schemaVersion": 1,
   "id": "60033f09-c2a4-490a-a3c3-d7167ce9f718",
   "createdAt": "2026-10-26T01:48:44.831Z",
   "targetId": "example-refund-only",
   "targetName": "Example support app (a refund and nothing else)",
   "build": "example support app, local test build",
   "applicationId": "example-support",
   "suiteId": "example-refund-only-contracts",
   "suiteHash": "aad7c8006040707ba2b28f25cf74c23b473708e7e56e107af26f84e41cef8493",
   "policyHash": "aad7c8006040707ba2b28f25cf74c23b473708e7e56e107af26f84e41cef8493",
   "profileHash": "e6c783b40d971f560f0b1d8c07765eec46710a30d93345f4afa3d9b38d89ce1b",
   "contextId": "synthetic-two-company",
   "fixtureVersion": "operator-declared-context/1",
   "fixtureHash": "419c1745c53e62eb804cc8c8a6e3cf04b531b40d368a97ddec21f3949e282666",
   "adapterVersion": "loopback-response-contract/3",
   "assertionSchemaVersion": "http-contract/4",
   "evaluatorHash": "15f1d937828a478b33e4ac684477e0a2cdd27c49db91e1b7fcb04f8c1a03d612",
   "requiredControlIds": [
    "B-WHOAMI",
    "B-OWN-REFUND",
    "B-OWN-REFUND-AFTER"
   ],
   "evidenceOrigin": "local-http-response",
   "runtimeMode": "configured-local-application",
   "targetBuildHash": null,
   "targetConfigHash": "ed448a7b15082beb3af3c5b269c32a25acc85b5b834f981308e0287871a300d2",
   "buildIdentity": "Declared in configuration; not independently attested.",
   "targetContext": "local-app",
   "targetLabel": null,
   "scopeLabel": "HTTP response contracts plus declared observers. Backend effects count only where an authoritative observer decided them. Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: app-audit 500 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
   "observers": [
    {
     "id": "app-audit",
     "type": "sqlite-audit",
     "settleMs": 500
    }
   ],
   "settlement": {
    "schema": "scopehaven-settlement/1",
    "settleMs": 500,
    "gaps": [
     {
      "after": null,
      "before": "B-OWN-REFUND",
      "windows": [
       {
        "source": "sql-audit-table",
        "instanceId": "sqlite-audit-app-audit",
        "scope": {
         "operations": [
          "insert",
          "update",
          "delete",
          "send"
         ],
         "names": null,
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 500,
        "lineage": {
         "observer": "sqlite-audit-table",
         "independence": "application-store"
        }
       }
      ]
     },
     {
      "after": "B-OWN-REFUND",
      "before": "B-REFUND-ONLY",
      "windows": [
       {
        "source": "sql-audit-table",
        "instanceId": "sqlite-audit-app-audit",
        "scope": {
         "operations": [
          "insert",
          "update",
          "delete",
          "send"
         ],
         "names": null,
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 500,
        "lineage": {
         "observer": "sqlite-audit-table",
         "independence": "application-store"
        }
       }
      ]
     },
     {
      "after": "B-REFUND-ONLY",
      "before": "B-OWN-REFUND-AFTER",
      "windows": [
       {
        "source": "sql-audit-table",
        "instanceId": "sqlite-audit-app-audit",
        "scope": {
         "operations": [
          "insert",
          "update",
          "delete",
          "send"
         ],
         "names": null,
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 500,
        "lineage": {
         "observer": "sqlite-audit-table",
         "independence": "application-store"
        }
       }
      ]
     },
     {
      "after": "B-OWN-REFUND-AFTER",
      "before": null,
      "windows": [
       {
        "source": "sql-audit-table",
        "instanceId": "sqlite-audit-app-audit",
        "scope": {
         "operations": [
          "insert",
          "update",
          "delete",
          "send"
         ],
         "names": null,
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 500,
        "lineage": {
         "observer": "sqlite-audit-table",
         "independence": "application-store"
        }
       }
      ]
     }
    ]
   },
   "catalog": {
    "schema": "scopehaven-catalog-identity/1",
    "sha256": "cef1d6acef34e9fdffbd63e0e667e1958a697cf5e210104f8c66f25e3d485ec0",
    "observers": [
     {
      "schema": "scopehaven-catalog/1",
      "engine": "sqlite",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "kinds": {
       "table": {
        "objects": 1,
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
       },
       "index": {
        "objects": 1,
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
       },
       "view": {
        "objects": 1,
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
       },
       "trigger": {
        "objects": 1,
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
       },
       "pragma": {
        "objects": 1,
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
       }
      },
      "final": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "changedDuringRun": false,
      "excluded": {
       "schemas": [],
       "tables": []
      },
      "instanceId": "sqlite-audit-app-audit"
     }
    ]
   },
   "durationMs": 2024,
   "checksTotal": 4,
   "counts": {
    "pass": 0,
    "fail": 4,
    "inconclusive": 0,
    "error": 0,
    "not_applicable": 0
   },
   "results": [
    {
     "id": "B-WHOAMI",
     "title": "Agent B session is agent B",
     "category": "Identity",
     "severity": "control",
     "status": "fail",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "pass",
       "expected": "HTTP 200",
       "actual": "HTTP 200"
      },
      {
       "name": "json.equals predicate 1",
       "status": "fail",
       "expected": "Configured JSON predicate holds",
       "actual": "Absent; type absent; predicate fail"
      },
      {
       "name": "Actor identity established by required controls",
       "status": "inconclusive",
       "expected": "The actor's identity, and any allowed use this check depends on, are established in this run",
       "actual": "An identity control did not pass before or after the actor's other checks"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [
       {
        "kind": "json.equals",
        "present": false,
        "type": "absent",
        "outcome": "fail"
       }
      ],
      "evidenceScope": "response-only"
     },
     "summary": "An observable response contract predicate failed.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates only.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "1e5fb801-3898-4117-94b3-349a4e4bdc02",
        "actorId": "agentB",
        "method": "GET",
        "requestPathHash": "9d0546e5bc40f03f2839ab91824bb64ab8df2b72c8a66a9841bbd02a1dfa5975",
        "routeSegments": [
         {
          "exact": "ff78282c592bbd027fba9099a0df7a4c9e4d48558f24a61e0130887d1be68f51",
          "keys": []
         },
         {
          "exact": "8189c9ae075285b86f63710b9e0cd241031244e8e1596ca9404544be372cfb20",
          "keys": [
           "b21d0244bce527edb7f1d36f07dd2cfc3da74076cc08c5df29b233ef9411ebf1"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "344efe7fc31ab825b9e6b3898dd7b0696e593fabb456baa305bd390fdf9fd698",
         "bodyKeys": "3682f153059214653a5a580a66d9597a228116c51a6aae63fd69cee0400849a3" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 2,
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
       "Check B-WHOAMI"
      ]
     },
     "durationMs": 0,
     "evidenceDigest": "e110915a010ed7cd2ec1fb2e6675d468f877d2b60d2874df1a134443d35af200",
     "decision": "fail"
    },
    {
     "id": "B-OWN-REFUND",
     "title": "Agent B requests a refund on Globex order B-1",
     "category": "Allowed use",
     "severity": "control",
     "status": "fail",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "fail",
       "expected": "HTTP 201",
       "actual": "HTTP 200"
      },
      {
       "name": "Observed effect 1 (effect.count)",
       "status": "inconclusive",
       "expected": "Exactly 1 matching committed effect(s)",
       "actual": "unobservable: No configured observer can see this effect.",
       "custody": null
      },
      {
       "name": "Actor identity established by required controls",
       "status": "inconclusive",
       "expected": "The actor's identity, and any allowed use this check depends on, are established in this run",
       "actual": "An identity control did not pass before or after the actor's other checks"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-and-observers"
     },
     "summary": "A response predicate or an observed effect failed.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates and observed effects.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "1f3da8b8-de10-4d7f-a6f3-fb042c66b5d5",
        "actorId": "agentB",
        "method": "POST",
        "requestPathHash": "698a5a37e11e196db92b43f34046252423355b2028a44cabbd51d621b361eba3",
        "routeSegments": [
         {
          "exact": "ff78282c592bbd027fba9099a0df7a4c9e4d48558f24a61e0130887d1be68f51",
          "keys": []
         },
         {
          "exact": "9608b7a00f81a7c20225bca8ed40e67dab135e0b3cec6d1183400a956e20e60e",
          "keys": [
           "1ffdaf9c2527532d8ce7dbd0c8ad65d129a63fffaf49f34966947f43435b50bd",
           "2f8f3a3bfde292024e92db9677b890da7360fb9051b4ae594f8bbfec9f2165ec",
           "c459a990cef44b9f198aada230b0151c7df0c318300572f42f4d18f4708abf64",
           "d99df014c50fb290f775e0653b97337186e3268a631878fb1dcccb6ed1532139"
          ]
         },
         {
          "exact": "0ddd1a07f94c115c860fed0e19bcf75d949808ddfd190bda9339e1204574ae8e",
          "keys": [
           "097be9cdc352f17bb20e79d34ea5970e0ff8da2079ea6f26a6b24ee62d5d1c85"
          ]
         },
         {
          "exact": "e1d97f094f2e3b911d0ea56a7b342c28da25ae8fc2f42b6b860fc77f62d0cd08",
          "keys": [
           "0e331fa8bd22f1099f86a0654faba6beaf27e8db9afc2d020c36d7efec7c1e35",
           "3e3af33f5893584eb96dbd1359b878f29fa874d17f52b4d7800b25aa4912a5e6",
           "4f5da66008e38bef9abe8cea56f43941a6d542aff346d5b1a5a73172aa544fe0",
           "5700f21766b7ecb10b3c37cabb42cea0258759a589e4d74df9268cf86d1a663f",
           "765ba7bdf436dd7ac7ea9717ad349941edb031ed29648fe7a0d1d9fbc911dd9d",
           "ed97fd9442441f6c88ef3e5c1a5783930240fe1dd8de00411609b5674ce22175"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "81180f59a9a38303df665c42292d817241487ecd260e5634aa9013f03177553f",
         "bodyKeys": "3682f153059214653a5a580a66d9597a228116c51a6aae63fd69cee0400849a3" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 2,
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
          "kind": "effect.count",
          "select": {
           "source": "sql-audit-table",
           "actor": "agent-b",
           "name": "refund.create",
           "resource": "orders/B-1"
          },
          "expected": 1,
          "verdict": "unobservable",
          "matched": 0,
          "custody": null
         }
        ],
        "windows": [
         {
          "source": "sql-audit-table",
          "instanceId": "sqlite-audit-app-audit",
          "scope": {
           "operations": [
            "insert",
            "update",
            "delete",
            "send"
           ],
           "names": null,
           "actorAttribution": "none",
           "evidence": "authoritative"
          },
          "coverage": "complete",
          "reason": null,
          "events": [],
          "settleMs": 500,
          "lineage": {
           "observer": "sqlite-audit-table",
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
       "Check B-OWN-REFUND"
      ]
     },
     "durationMs": 503,
     "evidenceDigest": "eb2260b44df9e61dfecf090b5c777a7aad5c7129d7dd360116776f14ccaf9672",
     "decision": "fail"
    },
    {
     "id": "B-REFUND-ONLY",
     "title": "A refund on Globex order B-2 changes nothing else",
     "category": "Collateral",
     "severity": "high",
     "status": "fail",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "fail",
       "expected": "HTTP 201",
       "actual": "HTTP 200"
      },
      {
       "name": "Trusted backend observation available",
       "status": "inconclusive",
       "expected": "Independent backend evidence required",
       "actual": "Backend evidence unavailable"
      },
      {
       "name": "Observed effect 1 (effect.only)",
       "status": "inconclusive",
       "expected": "Every committed effect is an expected one within its count, or allowed",
       "actual": "unobservable: No authoritative observer with a declared name vocabulary covers insert, update, delete, send, so none can vouch that nothing else happened.",
       "custody": null
      },
      {
       "name": "Actor identity established by required controls",
       "status": "inconclusive",
       "expected": "The actor's identity, and any allowed use this check depends on, are established in this run",
       "actual": "An identity control did not pass before or after the actor's other checks"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-and-observers"
     },
     "summary": "A response predicate or an observed effect failed.",
     "evidenceRequirement": "backend",
     "expected": "Configured response predicates and independent backend evidence.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "1ec34e3b-9053-4c44-ae04-5182bb010997",
        "actorId": "agentB",
        "method": "POST",
        "requestPathHash": "ad0c7deb95dac0b15715551bb43343157565523e954bc24c86ab4b4c58936bc2",
        "routeSegments": [
         {
          "exact": "ff78282c592bbd027fba9099a0df7a4c9e4d48558f24a61e0130887d1be68f51",
          "keys": []
         },
         {
          "exact": "9608b7a00f81a7c20225bca8ed40e67dab135e0b3cec6d1183400a956e20e60e",
          "keys": [
           "1ffdaf9c2527532d8ce7dbd0c8ad65d129a63fffaf49f34966947f43435b50bd",
           "2f8f3a3bfde292024e92db9677b890da7360fb9051b4ae594f8bbfec9f2165ec",
           "c459a990cef44b9f198aada230b0151c7df0c318300572f42f4d18f4708abf64",
           "d99df014c50fb290f775e0653b97337186e3268a631878fb1dcccb6ed1532139"
          ]
         },
         {
          "exact": "8124b92a0a4f1b42b1648d689664f6289307d92dbfead8062392144a61d996ce",
          "keys": [
           "097be9cdc352f17bb20e79d34ea5970e0ff8da2079ea6f26a6b24ee62d5d1c85"
          ]
         },
         {
          "exact": "e1d97f094f2e3b911d0ea56a7b342c28da25ae8fc2f42b6b860fc77f62d0cd08",
          "keys": [
           "0e331fa8bd22f1099f86a0654faba6beaf27e8db9afc2d020c36d7efec7c1e35",
           "3e3af33f5893584eb96dbd1359b878f29fa874d17f52b4d7800b25aa4912a5e6",
           "4f5da66008e38bef9abe8cea56f43941a6d542aff346d5b1a5a73172aa544fe0",
           "5700f21766b7ecb10b3c37cabb42cea0258759a589e4d74df9268cf86d1a663f",
           "765ba7bdf436dd7ac7ea9717ad349941edb031ed29648fe7a0d1d9fbc911dd9d",
           "ed97fd9442441f6c88ef3e5c1a5783930240fe1dd8de00411609b5674ce22175"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "21574bd71950dc0ec17aa967fe51c5f31fabd54b569d6297c8443d2bb31859c8",
         "bodyKeys": "3682f153059214653a5a580a66d9597a228116c51a6aae63fd69cee0400849a3" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 2,
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
          "kind": "effect.only",
          "expect": [
           {
            "select": {
             "source": "sql-audit-table",
             "actor": "agent-b",
             "operation": "insert",
             "name": "refund.create",
             "resource": "orders/B-2"
            },
            "count": 1
           }
          ],
          "allow": [],
          "verdict": "unobservable",
          "matched": 0,
          "counts": {
           "judged": 0,
           "expected": 0,
           "allowed": 0,
           "offending": 0,
           "unattributable": 0,
           "transient": 0
          },
          "custody": null
         }
        ],
        "windows": [
         {
          "source": "sql-audit-table",
          "instanceId": "sqlite-audit-app-audit",
          "scope": {
           "operations": [
            "insert",
            "update",
            "delete",
            "send"
           ],
           "names": null,
           "actorAttribution": "none",
           "evidence": "authoritative"
          },
          "coverage": "complete",
          "reason": null,
          "events": [],
          "settleMs": 500,
          "lineage": {
           "observer": "sqlite-audit-table",
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
       "Check B-REFUND-ONLY"
      ]
     },
     "durationMs": 503,
     "evidenceDigest": "d5e15a82f8b883425893ca163ff38d8dbca5c4470842e655c5de5893305e75e6",
     "decision": "fail"
    },
    {
     "id": "B-OWN-REFUND-AFTER",
     "title": "Agent B requests a refund on Globex order B-3 (after the collateral check)",
     "category": "Allowed use",
     "severity": "control",
     "status": "fail",
     "assertions": [
      {
       "name": "HTTP status matches contract",
       "status": "fail",
       "expected": "HTTP 201",
       "actual": "HTTP 200"
      },
      {
       "name": "Observed effect 1 (effect.count)",
       "status": "inconclusive",
       "expected": "Exactly 1 matching committed effect(s)",
       "actual": "unobservable: No configured observer can see this effect.",
       "custody": null
      },
      {
       "name": "Actor identity established by required controls",
       "status": "inconclusive",
       "expected": "The actor's identity, and any allowed use this check depends on, are established in this run",
       "actual": "An identity control did not pass before or after the actor's other checks"
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-and-observers"
     },
     "summary": "A response predicate or an observed effect failed.",
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates and observed effects.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "d207311b-7501-4af8-8de8-e23433f213f0",
        "actorId": "agentB",
        "method": "POST",
        "requestPathHash": "bfb61c5cb01bedeea128402a6d6f6586c26801ea9c7c95408dcffe988cbc7dfe",
        "routeSegments": [
         {
          "exact": "ff78282c592bbd027fba9099a0df7a4c9e4d48558f24a61e0130887d1be68f51",
          "keys": []
         },
         {
          "exact": "9608b7a00f81a7c20225bca8ed40e67dab135e0b3cec6d1183400a956e20e60e",
          "keys": [
           "1ffdaf9c2527532d8ce7dbd0c8ad65d129a63fffaf49f34966947f43435b50bd",
           "2f8f3a3bfde292024e92db9677b890da7360fb9051b4ae594f8bbfec9f2165ec",
           "c459a990cef44b9f198aada230b0151c7df0c318300572f42f4d18f4708abf64",
           "d99df014c50fb290f775e0653b97337186e3268a631878fb1dcccb6ed1532139"
          ]
         },
         {
          "exact": "dfd1dda92eb05a27f46ee5f3e95d20221cc909ec48e9f8f666f53e7e2a78c51d",
          "keys": [
           "097be9cdc352f17bb20e79d34ea5970e0ff8da2079ea6f26a6b24ee62d5d1c85"
          ]
         },
         {
          "exact": "e1d97f094f2e3b911d0ea56a7b342c28da25ae8fc2f42b6b860fc77f62d0cd08",
          "keys": [
           "0e331fa8bd22f1099f86a0654faba6beaf27e8db9afc2d020c36d7efec7c1e35",
           "3e3af33f5893584eb96dbd1359b878f29fa874d17f52b4d7800b25aa4912a5e6",
           "4f5da66008e38bef9abe8cea56f43941a6d542aff346d5b1a5a73172aa544fe0",
           "5700f21766b7ecb10b3c37cabb42cea0258759a589e4d74df9268cf86d1a663f",
           "765ba7bdf436dd7ac7ea9717ad349941edb031ed29648fe7a0d1d9fbc911dd9d",
           "ed97fd9442441f6c88ef3e5c1a5783930240fe1dd8de00411609b5674ce22175"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": true,
         "recordPredicates": [],
         "sentRoute": "a4943508034c7ebc69e4cdf11508002a22b0aa84b4c05b3a7321310c2a84eecc",
         "bodyKeys": "3682f153059214653a5a580a66d9597a228116c51a6aae63fd69cee0400849a3" // gitleaks:allow (a sealed digest of a response's key set, not a key)
        },
        "credentialMode": "bearer",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 2,
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
          "kind": "effect.count",
          "select": {
           "source": "sql-audit-table",
           "actor": "agent-b",
           "name": "refund.create",
           "resource": "orders/B-3"
          },
          "expected": 1,
          "verdict": "unobservable",
          "matched": 0,
          "custody": null
         }
        ],
        "windows": [
         {
          "source": "sql-audit-table",
          "instanceId": "sqlite-audit-app-audit",
          "scope": {
           "operations": [
            "insert",
            "update",
            "delete",
            "send"
           ],
           "names": null,
           "actorAttribution": "none",
           "evidence": "authoritative"
          },
          "coverage": "complete",
          "reason": null,
          "events": [],
          "settleMs": 500,
          "lineage": {
           "observer": "sqlite-audit-table",
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
       "Check B-OWN-REFUND-AFTER"
      ]
     },
     "durationMs": 502,
     "evidenceDigest": "7665c895fe0151b171a1e29e60954ae7f7ef58a133247362a19d0f6d6701225d",
     "decision": "fail"
    }
   ],
   "identityEvidence": {
    "schema": "actor-identity/6",
    "actors": [
     {
      "actorId": "agentB",
      "credentialMode": "bearer",
      "requiredControlIds": [
       "B-WHOAMI",
       "B-OWN-REFUND",
       "B-OWN-REFUND-AFTER"
      ],
      "identityControlIds": [
       "B-WHOAMI"
      ],
      "surfaceControlIds": [],
      "refusesWith401": false,
      "refusalStatuses": [
       401,
       403
      ],
      "before": [
       {
        "controlId": "B-WHOAMI",
        "kind": "before",
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
      "between": [
       {
        "afterCheckId": "B-OWN-REFUND",
        "probes": [
         {
          "controlId": "B-WHOAMI",
          "kind": "between",
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
        ]
       },
       {
        "afterCheckId": "B-REFUND-ONLY",
        "probes": [
         {
          "controlId": "B-WHOAMI",
          "kind": "between",
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
        ]
       }
      ],
      "after": [
       {
        "controlId": "B-WHOAMI",
        "kind": "after",
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
      "anonymous": [
       {
        "controlId": "B-WHOAMI",
        "kind": "anonymous",
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
      "invalid": [
       {
        "controlId": "B-WHOAMI",
        "kind": "invalid",
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
      "cross": [],
      "reason": "identity-control-not-passed",
      "loginProven": false,
      "established": false
     }
    ]
   },
   "principals": {
    "agentB": "agent-b"
   },
   "limitations": [
    "The connector assessed an operator-configured local application using HTTP response predicates; it did not independently observe backend retrieval or tool effects.",
    "Application, actor, build and data-context identities are declared by the profile. The target may have its own model, database or network dependencies.",
    "A passing response contract is not a security certification. Requirements needing backend evidence remain inconclusive when response predicates pass.",
    "Raw request/response content and credentials are not retained. Reproducing a predicate requires the original private profile and comparable target state.",
    "Requests run once without retries or automatic reset. A timed-out POST, PUT, PATCH or DELETE may still have executed; inspect the target before retrying manually.",
    "Observed effects are judged from the declared observers only. Traces and tool-call logs can show an effect happened; only an audit log, the application database or the request-path gate can show it did not, and a missing or presence-only observer leaves the effect unverifiable, never a pass.",
    "Custody: in a boundary check (any severity except control), an observed effect passes only when an observer that decided it keeps its record outside the application (the hold gate, an egress recorder or an SMTP sink). One decided only by records the application can write (its audit logs, its database, its traces or tool-call logs) reads inconclusive. Allowed-use controls keep their verdicts and carry custody as a tag only: a record the application can write may show an allowed action happened when it did not.",
    "Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: app-audit 500 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
    "A credentialed actor's login counts only with positive evidence in the same run: a required GET control returning its declared identity, refused without a credential, with an invalid credential (a random look-alike of the actor's own, made fresh each run) and with each other actor's credential, and passing again with the actor's surface controls (its other required GET controls, on protected routes) at a probe point before the actor's first other check and after each of them, each probe in full. Identity is judged per check (actor-identity/5): a check rests on that identity route proof and on the two probe points around it. A point that did not pass withholds the checks it covers, ranked across both of a check's points, except that a required control is withheld only for a login-level reason (an identity probe that did not pass or did not finish at a point covering it, or a probe refused at any point), never because a surface probe failed for another reason; a check whose own two points passed keeps its status when another point fails. A probe refused with the actor's own credential at any point withholds every check of the actor, required and identity controls included, since a credential that flaps can be refused between two accepting points: a refused identity probe (401, 403, its declared sign-in redirect, or a complete 2xx that names another principal or none) reads bracket-not-passed, a refused surface probe (401, 403 or the declared redirect: the protected routes did not accept the credential the identity route accepted) reads surface-refused, and bracket-not-passed when both were refused. A surface probe that fails otherwise (a 500, a 404) leaves the checks its point covers not established. A withheld check is inconclusive; a boundary check whose refusal was observed while its identity or allowed use was not established is the distinct decision prohibition-observed-identity-unproven, never a pass. The gate reports identity-not-established for an actor whose route or any point did not hold, and a comparison never labels a row restored or fixed when its identity was not proven for it. A credentialed 401 on a boundary check is an authentication failure, not a refusal, unless the actor declares refusesWith401 and a surface control brackets its checks. A 403 or any other answer outside 2xx counts as a refusal only after the same actor's complete 2xx on a protected route (a surface control in its probe points); without one it is inconclusive. An outage strictly between the two probe points that cover a check is not detected. Evidence of credential loss on an actor's own main rows, rather than at a probe point, stays row-level: a credentialed 401 on a boundary check (unauthenticated-401), a redirect to the declared sign-in, or a required control answering a refusal status withholds or fails that row, and the gate fails, but a comparison may still credit other rows of that actor, and a change or a captured value that actor made still counts as attributed."
   ]
  }
 },
 "appLog": {
  "profile": {
   "id": "app-log-admission",
   "name": "App log admission",
   "applicationId": "app-log-admission",
   "origin": "http://127.0.0.1:9",
   "buildLabel": "b1",
   "contextId": "synthetic-app-log",
   "actors": {
    "member": {
     "principalId": "member-1"
    }
   },
   "requiredControlIds": [
    "WHOAMI",
    "CHECKOUT"
   ],
   "observers": [
    {
     "id": "sink",
     "type": "egress-recorder",
     "port": 40999,
     "routing": "proxy",
     "destinations": [
      {
       "host": "pay.example",
       "paths": [
        "/v1/refunds"
       ]
      },
      {
       "host": "shop.example",
       "paths": [
        "/v1/orders"
       ]
      }
     ],
     "witness": {
      "actorId": "member",
      "method": "GET",
      "path": "/ping",
      "host": "witness.scopehaven.invalid"
     },
     "settleMs": 250
    }
   ],
   "appLogs": [
    {
     "id": "actions",
     "use": "admission",
     "log": {
      "file": {
       "path": "/tmp/scopehaven nc12 app log N2Kqfk/actions.jsonl"
      }
     },
     "fields": {
      "action": "/event",
      "outcome": "/result",
      "actor": "/actor"
     },
     "outcomes": {
      "committed": [
       "ok"
      ],
      "error": [
       "error"
      ]
     },
     "rules": [
      {
       "action": "refund.paid",
       "operation": "send",
       "vocabulary": "egress",
       "name": "pay.example",
       "resource": "POST /v1/refunds",
       "observedAs": [
        "http-egress"
       ]
      },
      {
       "action": "carol.suspended",
       "operation": "send",
       "vocabulary": "egress",
       "name": "sync.desk.example",
       "resource": "POST /suspend/",
       "observedAs": [
        "http-egress"
       ]
      }
     ],
     "logActors": {
      "member-1": "member-1"
     }
    }
   ],
   "checks": [
    {
     "id": "WHOAMI",
     "title": "WHOAMI",
     "category": "allowed-use",
     "severity": "control",
     "actorId": "member",
     "method": "GET",
     "path": "/me",
     "evidenceRequirement": "response",
     "assertions": [
      {
       "kind": "status.equals",
       "expected": 200
      }
     ]
    },
    {
     "id": "CHECKOUT",
     "title": "CHECKOUT",
     "category": "allowed-use",
     "severity": "control",
     "actorId": "member",
     "method": "POST",
     "path": "/checkout",
     "body": {},
     "evidenceRequirement": "response",
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
        "source": "http-egress",
        "operation": "send",
        "name": "shop.example"
       }
      }
     ]
    },
    {
     "id": "NO-PAY",
     "title": "NO-PAY",
     "category": "object-access",
     "severity": "high",
     "actorId": "member",
     "method": "POST",
     "path": "/summarize",
     "body": {},
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
        "source": "http-egress",
        "operation": "send",
        "name": "pay.example"
       }
      }
     ]
    },
    {
     "id": "NO-PAY-LATE",
     "title": "NO-PAY-LATE",
     "category": "object-access",
     "severity": "high",
     "actorId": "member",
     "method": "POST",
     "path": "/late",
     "body": {},
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
        "source": "http-egress",
        "operation": "send",
        "name": "pay.example"
       }
      }
     ]
    }
   ]
  },
  "contractDigest": "28e170cf27d4cb7dbb2456ac1eff2efbd1ddb77a459aff6642114d5bebbd94a8",
  "suite": {
   "id": "app-log-admission-contracts",
   "targetId": "app-log-admission",
   "applicationId": "app-log-admission",
   "version": "http-contract/4",
   "evidenceOrigin": "local-http-response",
   "hash": "28e170cf27d4cb7dbb2456ac1eff2efbd1ddb77a459aff6642114d5bebbd94a8",
   "scope": "Definition summary only; private request bodies, expected values, actor credentials and endpoints are omitted.",
   "requiredControlIds": [
    "WHOAMI",
    "CHECKOUT"
   ],
   "checks": [
    {
     "id": "WHOAMI",
     "title": "WHOAMI",
     "category": "allowed-use",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "GET",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "member",
     "credentialMode": "none",
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "CHECKOUT",
     "title": "CHECKOUT",
     "category": "allowed-use",
     "severity": "control",
     "evidenceRequirement": "response",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "member",
     "credentialMode": "none",
     "effects": [
      {
       "kind": "effect.exists",
       "select": {
        "source": "http-egress",
        "operation": "send",
        "name": "shop.example"
       }
      }
     ],
     "recordPredicates": [],
     "recordPartners": []
    },
    {
     "id": "NO-PAY",
     "title": "NO-PAY",
     "category": "object-access",
     "severity": "high",
     "evidenceRequirement": "backend",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "member",
     "credentialMode": "none",
     "effects": [
      {
       "kind": "effect.none",
       "select": {
        "source": "http-egress",
        "operation": "send",
        "name": "pay.example"
       }
      }
     ],
     "recordPredicates": []
    },
    {
     "id": "NO-PAY-LATE",
     "title": "NO-PAY-LATE",
     "category": "object-access",
     "severity": "high",
     "evidenceRequirement": "backend",
     "method": "POST",
     "assertionKinds": [
      "status.equals"
     ],
     "actorId": "member",
     "credentialMode": "none",
     "effects": [
      {
       "kind": "effect.none",
       "select": {
        "source": "http-egress",
        "operation": "send",
        "name": "pay.example"
       }
      }
     ],
     "recordPredicates": []
    }
   ],
   "identitySchema": "actor-identity/6",
   "principalsDigest": "239dac00c2cfa8a3efd632016b0bd5de13fb6d25cf5bbb252a358a70e15fee93",
   "observers": [
    {
     "id": "sink",
     "type": "egress-recorder",
     "settleMs": 250,
     "collector": {
      "label": "egress-recorder/12",
      "digest": "e853432b0bdf6ec48cd3d9a056446d05a081dfc5012c2b7c0c575d6b76a82758",
      "node": "24.21.0"
     }
    }
   ],
   "appLogs": [
    {
     "id": "actions",
     "use": "admission",
     "route": "file",
     "mappingDigest": "54baa262f38d09c9d51557e032e9f411a2bffd701fb05417f5daad227bd0d701",
     "scope": {
      "operations": [
       "send"
      ],
      "names": [
       "pay.example",
       "sync.desk.example"
      ],
      "actorAttribution": "principal",
      "evidence": "presence-only"
     },
     "principals": [
      "member-1"
     ],
     "projection": {
      "pay.example": [
       "http-egress"
      ],
      "sync.desk.example": [
       "http-egress"
      ]
     },
     "reads": {
      "values": {},
      "distinct": {},
      "exact": [
       "pay.example",
       "sync.desk.example"
      ],
      "perApplication": [],
      "trace": false,
      "backgroundAllows": []
     },
     "collector": {
      "label": "app-log/2",
      "digest": "3bed5d83a4a7bb24229cd6029fb4d01ef2972cab7714ba466e57a87c4fd99265",
      "node": "24.21.0"
     }
    }
   ],
   "targetContext": "local-app",
   "targetLabel": null,
   "runnableWith": "Use the original local profile with ./scopehaven assess --config <file> --target <id>. This redacted summary is not an executable profile."
  },
  "sarifDigest": "d91d75b4c2151cb4aa9f2a4ecaac53bbfc72b743d2291d9baee4b6adf1858451",
  "reportDigest": "493da80f6f43a321ca4a9cb2aa697dca1d00d4ebe8f1ffa19c2309828212276a",
  "run": {
   "schemaVersion": 1,
   "id": "a6044be7-8840-418f-be6e-1ff6aa964d78",
   "createdAt": "2026-10-26T01:48:45.950Z",
   "targetId": "app-log-admission",
   "targetName": "App log admission",
   "build": "b1",
   "applicationId": "app-log-admission",
   "suiteId": "app-log-admission-contracts",
   "suiteHash": "ea29efcd94d06ed67b84a67092ae9ca9e3e9394cce6add5d568f7ac59440c0c3",
   "policyHash": "ea29efcd94d06ed67b84a67092ae9ca9e3e9394cce6add5d568f7ac59440c0c3",
   "profileHash": "28e170cf27d4cb7dbb2456ac1eff2efbd1ddb77a459aff6642114d5bebbd94a8",
   "contextId": "synthetic-app-log",
   "fixtureVersion": "operator-declared-context/1",
   "fixtureHash": "44f28e2e2502452147c7015739b9dd0f2d10078f25baac96ef91046553d6c0f6",
   "adapterVersion": "loopback-response-contract/3",
   "assertionSchemaVersion": "http-contract/4",
   "evaluatorHash": "15f1d937828a478b33e4ac684477e0a2cdd27c49db91e1b7fcb04f8c1a03d612",
   "requiredControlIds": [
    "WHOAMI",
    "CHECKOUT"
   ],
   "evidenceOrigin": "local-http-response",
   "runtimeMode": "configured-local-application",
   "targetBuildHash": null,
   "targetConfigHash": "c2da7d6501076990e0b8621e1942b31ed0ca8213c973152f2fa077852e774f8b",
   "buildIdentity": "Declared in configuration; not independently attested.",
   "targetContext": "local-app",
   "targetLabel": null,
   "scopeLabel": "HTTP response contracts plus declared observers. Backend effects count only where an authoritative observer decided them. Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: sink 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
   "observers": [
    {
     "id": "sink",
     "type": "egress-recorder",
     "settleMs": 250,
     "collector": {
      "label": "egress-recorder/12",
      "digest": "e853432b0bdf6ec48cd3d9a056446d05a081dfc5012c2b7c0c575d6b76a82758",
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
      "before": "CHECKOUT",
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "pay.example",
          "shop.example"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     },
     {
      "after": "CHECKOUT",
      "before": "NO-PAY",
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "pay.example",
          "shop.example"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     },
     {
      "after": "NO-PAY",
      "before": "NO-PAY-LATE",
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "pay.example",
          "shop.example"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     },
     {
      "after": "NO-PAY-LATE",
      "before": null,
      "windows": [
       {
        "source": "http-egress",
        "instanceId": "egress-recorder-sink",
        "scope": {
         "operations": [
          "send"
         ],
         "names": [
          "pay.example",
          "shop.example"
         ],
         "actorAttribution": "none",
         "evidence": "authoritative"
        },
        "coverage": "complete",
        "reason": null,
        "events": [],
        "settleMs": 250,
        "lineage": {
         "observer": "http-egress-recorder",
         "independence": "request-path"
        }
       }
      ]
     }
    ]
   },
   "appLogs": [
    {
     "id": "actions",
     "use": "admission",
     "route": "file",
     "mappingDigest": "54baa262f38d09c9d51557e032e9f411a2bffd701fb05417f5daad227bd0d701",
     "scope": {
      "operations": [
       "send"
      ],
      "names": [
       "pay.example",
       "sync.desk.example"
      ],
      "actorAttribution": "principal",
      "evidence": "presence-only"
     },
     "principals": [
      "member-1"
     ],
     "projection": {
      "pay.example": [
       "http-egress"
      ],
      "sync.desk.example": [
       "http-egress"
      ]
     },
     "reads": {
      "values": {},
      "distinct": {},
      "exact": [
       "pay.example",
       "sync.desk.example"
      ],
      "perApplication": [],
      "trace": false,
      "backgroundAllows": []
     },
     "collector": {
      "label": "app-log/2",
      "digest": "3bed5d83a4a7bb24229cd6029fb4d01ef2972cab7714ba466e57a87c4fd99265",
      "node": "24.21.0"
     }
    }
   ],
   "durationMs": 1108,
   "checksTotal": 4,
   "counts": {
    "pass": 3,
    "fail": 1,
    "inconclusive": 0,
    "error": 0,
    "not_applicable": 0
   },
   "results": [
    {
     "id": "WHOAMI",
     "title": "WHOAMI",
     "category": "allowed-use",
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
        "requestId": "cd2647f5-6e3d-4982-ba92-986210be3aa9",
        "actorId": "member",
        "method": "GET",
        "requestPathHash": "b4104b822236e8acba1cec3b8531cb785a5a11300e229b22306ba70151590fe2",
        "routeSegments": [
         {
          "exact": "35e1076f9c8bd85fcb5a6951a45b1eb0df7fcdbfbb3b777c9a3e24e9d5b8f957",
          "keys": [
           "10f5c226a8a40cf9d3e9604341c0a0340ffa3e5d339faacca923c0713af06cfe"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "5d944e0402565581a3e8c6187292feba8a4289dffacd9741cc2e88b2837a7cad",
         "bodyKeys": null
        },
        "credentialMode": "none",
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
     "durationMs": 1,
     "evidenceDigest": "5d5bdcb75e9db429664bd1f8bbec09fdc365e2548a0b7fd9d0290d7d76eda645",
     "decision": "pass"
    },
    {
     "id": "CHECKOUT",
     "title": "CHECKOUT",
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
       "name": "Observed effect 1 (effect.exists)",
       "status": "pass",
       "expected": "A matching committed effect",
       "actual": "pass: An observer recorded the expected committed effect.",
       "custody": "independent"
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
     "evidenceRequirement": "response",
     "expected": "Configured HTTP response predicates and observed effects.",
     "backendEvidence": "observed",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "09d055e7-6c22-40ae-b9fb-2dd78de0eff0",
        "actorId": "member",
        "method": "POST",
        "requestPathHash": "3ff05a7ed82155e747c587aff28ce4d47f2d79cb6029fd20efdc9d1ffff11806",
        "routeSegments": [
         {
          "exact": "5d2cc808fb9369faa4906885670d23d2ee349d35b8f8ef6ac4ef6252a64ed8b7",
          "keys": [
           "1e59b9bf79169d5e9bccd1f49a7959880da8e1aa46f82fdd70faa1c732ffbfeb",
           "54e1f000d0a8f8692ac3b6ac449ee68847164703bdcbdd414294aeefd9895015",
           "a2e040555c19d9749c494767dfe3b1488c70af810d2682ca7b7e47043c00f8ee",
           "a6c6587af55ca822b93ffcb89a1fd272e3c7fd1e05be5e33979945fcf9b2410a",
           "d51b364b5e47e0556287eabc70e11d6bb66d7a245d52eb4abda7622c8f66ad2f",
           "e2ca1d03c7e371943115e6f771573d670c6bed25d7ad2c190c60bc572c13c1f9",
           "f28faa9d7bb68eedd5360c97a0e50a8686c7ef6db200b99baa7d792ea6ca84c9"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "a49bbde4b3e6aa1c0648b4245d48e771d3cbb691abee3ef8112d1b5bdfe430e9",
         "bodyKeys": null
        },
        "credentialMode": "none",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 10,
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
           "source": "http-egress",
           "operation": "send",
           "name": "shop.example"
          },
          "verdict": "pass",
          "matched": 1,
          "custody": "independent"
         }
        ],
        "windows": [
         {
          "source": "http-egress",
          "instanceId": "egress-recorder-sink",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "pay.example",
            "shop.example"
           ],
           "actorAttribution": "none",
           "evidence": "authoritative"
          },
          "coverage": "complete",
          "reason": null,
          "events": [
           {
            "schema": "scopehaven-effect/1",
            "source": "http-egress",
            "observer": {
             "kind": "http-egress-recorder",
             "instanceId": "egress-recorder-sink"
            },
            "seq": 1,
            "observedAt": "2026-10-26T01:48:45.105Z",
            "actor": null,
            "operation": "send",
            "name": "shop.example",
            "resource": "POST /v1/orders",
            "outcome": "committed",
            "correlation": {},
            "contentDigest": null
           }
          ],
          "settleMs": 250,
          "lineage": {
           "observer": "http-egress-recorder",
           "independence": "request-path"
          }
         }
        ],
        "appLogWindows": [
         {
          "source": "app-log",
          "instanceId": "app-log-actions",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "pay.example",
            "sync.desk.example"
           ],
           "actorAttribution": "principal",
           "evidence": "presence-only"
          },
          "coverage": "complete",
          "reason": null,
          "events": []
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
       "Check CHECKOUT"
      ]
     },
     "durationMs": 260,
     "evidenceDigest": "47ce89e40b204c515018d977140a01104e14663c8504ca0299d228f7ba475ffc",
     "decision": "pass"
    },
    {
     "id": "NO-PAY",
     "title": "NO-PAY",
     "category": "object-access",
     "severity": "high",
     "status": "fail",
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
       "status": "fail",
       "expected": "No matching committed effect",
       "actual": "fail: Every authoritative observer that can see this effect (egress-recorder-sink) covered the window and recorded no matching committed effect. Admission: the application's own action log (app log actions) records 1 committed action(s) of this check's own actor in its window that this clause forbids, so it fails (app-log-unobserved-admission; an observer held outside the application covered the window and recorded none). The application wrote that record.",
       "custody": "subject-writable",
       "appLog": {
        "finding": "app-log-unobserved-admission",
        "log": "actions",
        "entries": 1,
        "contradicts": true,
        "custodyVerdict": "pass"
       }
      }
     ],
     "observed": {
      "httpStatus": 200,
      "complete": true,
      "jsonParsed": true,
      "predicates": [],
      "evidenceScope": "response-and-observers"
     },
     "summary": "A response predicate or an observed effect failed.",
     "evidenceRequirement": "backend",
     "expected": "Configured response predicates and independent backend evidence.",
     "backendEvidence": "unavailable",
     "trace": [
      {
       "type": "http-observation",
       "label": "Retained response metadata; response content is not stored",
       "data": {
        "requestId": "26e3f406-2a5e-4a73-8eac-f31d97b07fe5",
        "actorId": "member",
        "method": "POST",
        "requestPathHash": "27e2bd6186f55c10663f14d3004d14d1390a1125d3955b55f19691f65e7ed5f0",
        "routeSegments": [
         {
          "exact": "eeddf9cad6ad5ad1bb985d4ee0e4a7d9bcb1fac950509b6bc994fc4997ab5362",
          "keys": [
           "3a089b3da210f82d442edceb1db507d34614fe9aa133f25abecb73c647014b6f",
           "3ffa92aed2405b4823f0bb7551e038856490502342f44c4d8ee1501417274900",
           "6a63e49bcff4b22fa3290df162497fa36f8f8714e2db2ccca767fd84d9bebf77",
           "85c89bbf21d4a8930e6d2551e6509af1060f7425e7b330efbf82ab52b3f474df",
           "a41dce4a4520db1de81e36cbdd860a77ab314c8202deb380ce4c605215d08ef6",
           "bf5e0a79ab597770aafe0bf0bbef2cf1d87e2f41c7da58c76d5f6f9c7adb6fb2",
           "ebd3e1d7b22fb33774b15b1ce6ae62f4f20a0f1860e35cbee0b2fa09b07362f9",
           "f56155d403fcc281acbf6e0912763c3672e3d0215f6369f1fc0b9172474371c3"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "772df7872eed8070901ad8255435378713bc2fa76e96ea699edd05311d716ce9",
         "bodyKeys": null
        },
        "credentialMode": "none",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 10,
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
          "kind": "effect.none",
          "select": {
           "source": "http-egress",
           "operation": "send",
           "name": "pay.example"
          },
          "verdict": "fail",
          "matched": 0,
          "custody": "subject-writable",
          "appLog": {
           "finding": "app-log-unobserved-admission",
           "log": "actions",
           "entries": 1,
           "contradicts": true,
           "custodyVerdict": "pass"
          }
         }
        ],
        "windows": [
         {
          "source": "http-egress",
          "instanceId": "egress-recorder-sink",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "pay.example",
            "shop.example"
           ],
           "actorAttribution": "none",
           "evidence": "authoritative"
          },
          "coverage": "complete",
          "reason": null,
          "events": [],
          "settleMs": 250,
          "lineage": {
           "observer": "http-egress-recorder",
           "independence": "request-path"
          }
         }
        ],
        "appLogWindows": [
         {
          "source": "app-log",
          "instanceId": "app-log-actions",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "pay.example",
            "sync.desk.example"
           ],
           "actorAttribution": "principal",
           "evidence": "presence-only"
          },
          "coverage": "complete",
          "reason": null,
          "events": [
           {
            "schema": "scopehaven-effect/1",
            "source": "app-log",
            "observer": {
             "kind": "app-action-log",
             "instanceId": "app-log-actions"
            },
            "seq": 128,
            "observedAt": "2026-10-26T01:48:45.429Z",
            "actor": "member-1",
            "operation": "send",
            "name": "pay.example",
            "resource": "POST /v1/refunds",
            "outcome": "committed",
            "correlation": {},
            "contentDigest": "e8c7833663ad4250eab37304a27aa8419c5770c392e3ed88a480a5b022d23a69"
           }
          ]
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
       "Check NO-PAY"
      ]
     },
     "durationMs": 321,
     "evidenceDigest": "a553bf7fa9f96ac038c7c85fcbdf75f0f6a763321f8e5937874a1ad7a9e68d68",
     "decision": "fail"
    },
    {
     "id": "NO-PAY-LATE",
     "title": "NO-PAY-LATE",
     "category": "object-access",
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
       "name": "Trusted backend observation available",
       "status": "pass",
       "expected": "Independent backend evidence required",
       "actual": "Authoritative observers decided every declared effect"
      },
      {
       "name": "Observed effect 1 (effect.none)",
       "status": "pass",
       "expected": "No matching committed effect",
       "actual": "pass: Every authoritative observer that can see this effect (egress-recorder-sink) covered the window and recorded no matching committed effect.",
       "custody": "independent"
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
        "requestId": "26f861f1-f512-42ac-8d4d-13d24357ae23",
        "actorId": "member",
        "method": "POST",
        "requestPathHash": "922da75e6c356b21350a6ca9315b03e118db36fc9c435efa3e34a7285f40f952",
        "routeSegments": [
         {
          "exact": "85c834ea0d09476a212114a125250025f4262471a1b8fdd30591d74e96dcf3df",
          "keys": [
           "42d521c01b183c939cbad7a2b889f1d96c985da69acbea595c03357030901fe9",
           "e9f9db87e9114db697bb50f80b5320b9b3a2de5b4344181a943eb22076ccb118"
          ]
         }
        ],
        "controlScope": {
         "cleanObject": false,
         "recordPredicates": [],
         "sentRoute": "fbb5065a9ccee4da47639d3e4611e62d3ec6fd670117aa95203b75d7289be15c",
         "bodyKeys": null
        },
        "credentialMode": "none",
        "requestTimeoutMs": 3000,
        "httpStatus": 200,
        "responseComplete": true,
        "responseBytes": 10,
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
          "kind": "effect.none",
          "select": {
           "source": "http-egress",
           "operation": "send",
           "name": "pay.example"
          },
          "verdict": "pass",
          "matched": 0,
          "custody": "independent"
         }
        ],
        "windows": [
         {
          "source": "http-egress",
          "instanceId": "egress-recorder-sink",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "pay.example",
            "shop.example"
           ],
           "actorAttribution": "none",
           "evidence": "authoritative"
          },
          "coverage": "complete",
          "reason": null,
          "events": [],
          "settleMs": 250,
          "lineage": {
           "observer": "http-egress-recorder",
           "independence": "request-path"
          }
         }
        ],
        "appLogWindows": [
         {
          "source": "app-log",
          "instanceId": "app-log-actions",
          "scope": {
           "operations": [
            "send"
           ],
           "names": [
            "pay.example",
            "sync.desk.example"
           ],
           "actorAttribution": "principal",
           "evidence": "presence-only"
          },
          "coverage": "complete",
          "reason": null,
          "events": []
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
       "Check NO-PAY-LATE"
      ]
     },
     "durationMs": 260,
     "evidenceDigest": "0eb7964f8b2f51b81c8805e76c9ef1cb9005bf6935cbf11b0c3ab4a1cbd8df1e",
     "decision": "pass"
    }
   ],
   "identityEvidence": {
    "schema": "actor-identity/6",
    "actors": []
   },
   "principals": {
    "member": "member-1"
   },
   "limitations": [
    "The connector assessed an operator-configured local application using HTTP response predicates; it did not independently observe backend retrieval or tool effects.",
    "Application, actor, build and data-context identities are declared by the profile. The target may have its own model, database or network dependencies.",
    "A passing response contract is not a security certification. Requirements needing backend evidence remain inconclusive when response predicates pass.",
    "Raw request/response content and credentials are not retained. Reproducing a predicate requires the original private profile and comparable target state.",
    "Requests run once without retries or automatic reset. A timed-out POST, PUT, PATCH or DELETE may still have executed; inspect the target before retrying manually.",
    "Egress recorders (sink: proxy routing, quietMs 300 ms) are loopback sinks for the app's outbound HTTP, each holding its port on both 127.0.0.1 and [::1] (a recorder that cannot bind both does not start): they answer every request themselves and never forward it, so a recorded send is the app's attempt, not a delivery. Events name the destination host and a declared path prefix (raw paths and bodies are digested, never stored, except the body fields a destination declares for capture). Absence is claimed only with declared routing and this window's witness (an app request that makes the app send one tagged outbound request): the witness proves the route was live for that request, not that the app has no other way out; for that, run the app on a network whose only exit is the sink. A proxy request whose Host header names another host than its URL, or that addresses an undeclared IP literal, leaves the window partial. An HTTPS tunnel request (CONNECT) is recorded by host and refused, and its payload is never seen, so the window is partial. Declared test-mode replies (static JSON) stand in for a provider's answers; no real provider is contacted. A send made later than quietMs after the last arrival is not observed.",
    "App action logs (actions): the target declared the application's own action log, a file the application appends one line per action to. ScopeHaven reads each check's lines (from just before its request to just after its window ends, before any witness request) and seals them beside the check's observer windows, mapped to effects by the declared rules and actor map. The application writes this log, so its lines are app-reported, never custody evidence: they never enter a custody decision, never make, extend or rescue a pass, and an application that writes a false log defeats anything they would say. With \"use\": \"admission\" the log is read against the application only: a clause that did not fail reads fail when the log records, as committed, an action of the check's own actor in the check's own window that the clause forbids (app-log-unobserved-admission; the clause names the log as its source and its custody is the application's). A countBy clause is read only on lines declared one per application. An own line that fits an actor-pinned background source's shape counts only where the check's own window names the job's principal (or custody saw nothing the job could be) and the line carries the check's own correlation token, and an allowBackground allow never excuses the check's own actor. A field read from the line counts only through its declared word map, and an effect.only clause whose selectors the log cannot all read judges only entries its rules declare distinct from them. Entries of another actor, of a declared background source, that fit a declared effect or claim of an earlier check by the same actor, or logged after the cut are never admissions (an earlier check that declares neither offers nothing to set its late line aside), and a baseline fail that rests only on admissions never credits a repair.",
    "Absence passes an egress recorder or SMTP sink decides: routing declared, not shown exclusive. Such a pass shows that the declared route was live (the window's witness reached the sink through it) and carried no matching send, not that the application made no such call by another way out (a direct connection, another address, port or socket, or a client or child process that ignores the route); for that, run the application where the sink is its only way out. Each such pass is also bounded in time: it covers sends recorded from its check's start through the run's final mark (its own window held for the declared settle or effect horizon after its response), and says nothing about a send made after the final mark. The report, SARIF, the comparison export and the gate summary name each such row.",
    "Observed effects are judged from the declared observers only. Traces and tool-call logs can show an effect happened; only an audit log, the application database or the request-path gate can show it did not, and a missing or presence-only observer leaves the effect unverifiable, never a pass.",
    "Custody: in a boundary check (any severity except control), an observed effect passes only when an observer that decided it keeps its record outside the application (the hold gate, an egress recorder or an SMTP sink). One decided only by records the application can write (its audit logs, its database, its traces or tool-call logs) reads inconclusive. Allowed-use controls keep their verdicts and carry custody as a tag only: a record the application can write may show an allowed action happened when it did not.",
    "Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs (settleMs: sink 250 ms), and seals the gaps between the checks' windows. A committed effect matching a passed effect.none or effect.count clause after that clause's window closed (in a gap, a later check's window or the tail) withholds the pass as inconclusive (effect-outside-window); so does an effect.exists or effect.count pass whose matched effect also fits an earlier check's selector (effect-ambiguous-attribution), an effect.only pass followed by any later committed effect of an operation it judged (effect-outside-window), and an absence whose deciding observer could not decide absence in a later window, because that window failed, was partial or was not exact for the selector (settlement-unobserved). Allowed-use controls carry these findings as tags only. Effects committed after the final mark are outside every window and every claim. Pin a resource or actor on each clause so one check's effects cannot match another's.",
    "A credentialed actor's login counts only with positive evidence in the same run: a required GET control returning its declared identity, refused without a credential, with an invalid credential (a random look-alike of the actor's own, made fresh each run) and with each other actor's credential, and passing again with the actor's surface controls (its other required GET controls, on protected routes) at a probe point before the actor's first other check and after each of them, each probe in full. Identity is judged per check (actor-identity/5): a check rests on that identity route proof and on the two probe points around it. A point that did not pass withholds the checks it covers, ranked across both of a check's points, except that a required control is withheld only for a login-level reason (an identity probe that did not pass or did not finish at a point covering it, or a probe refused at any point), never because a surface probe failed for another reason; a check whose own two points passed keeps its status when another point fails. A probe refused with the actor's own credential at any point withholds every check of the actor, required and identity controls included, since a credential that flaps can be refused between two accepting points: a refused identity probe (401, 403, its declared sign-in redirect, or a complete 2xx that names another principal or none) reads bracket-not-passed, a refused surface probe (401, 403 or the declared redirect: the protected routes did not accept the credential the identity route accepted) reads surface-refused, and bracket-not-passed when both were refused. A surface probe that fails otherwise (a 500, a 404) leaves the checks its point covers not established. A withheld check is inconclusive; a boundary check whose refusal was observed while its identity or allowed use was not established is the distinct decision prohibition-observed-identity-unproven, never a pass. The gate reports identity-not-established for an actor whose route or any point did not hold, and a comparison never labels a row restored or fixed when its identity was not proven for it. A credentialed 401 on a boundary check is an authentication failure, not a refusal, unless the actor declares refusesWith401 and a surface control brackets its checks. A 403 or any other answer outside 2xx counts as a refusal only after the same actor's complete 2xx on a protected route (a surface control in its probe points); without one it is inconclusive. An outage strictly between the two probe points that cover a check is not detected. Evidence of credential loss on an actor's own main rows, rather than at a probe point, stays row-level: a credentialed 401 on a boundary check (unauthenticated-401), a redirect to the declared sign-in, or a required control answering a refusal status withholds or fails that row, and the gate fails, but a comparison may still credit other rows of that actor, and a change or a captured value that actor made still counts as attributed."
   ]
  }
 }
};
