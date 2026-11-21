# IOC Triage Report

> Local-feed matches are triage signals, not proof of compromise. Indicators are defanged.

| Indicator | Type | Score | Band | Human review |
|---|---:|---:|---|---|
| `198[.]51[.]100[.]10` | ip | 90 | high | Yes |

**Evidence:** demo_feed_alpha (phishing), demo_feed_beta (phishing)
**Reasons:** Listed in at least one local feed (+20); Listed by 2 or more independent feed files (+25); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1566 Phishing
**Analyst note:** Evidence: 2 local feed match(es). ATT&CK mappings: T1566. Next step: analyst review and corroboration with internal telemetry.

| `198[.]51[.]100[.]44` | ip | 90 | high | Yes |

**Evidence:** demo_feed_alpha (botnet), demo_feed_beta (botnet), demo_feed_gamma (botnet)
**Reasons:** Listed in at least one local feed (+20); Listed by 2 or more independent feed files (+25); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1584 Compromise Infrastructure
**Analyst note:** Evidence: 3 local feed match(es). ATT&CK mappings: T1584. Next step: analyst review and corroboration with internal telemetry.

| `203[.]0[.]113[.]20` | ip | 90 | high | Yes |

**Evidence:** demo_feed_alpha (malware-c2), demo_feed_beta (command-and-control), demo_feed_gamma (malware-c2)
**Reasons:** Listed in at least one local feed (+20); Listed by 2 or more independent feed files (+25); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1071 Application Layer Protocol
**Analyst note:** Evidence: 3 local feed match(es). ATT&CK mappings: T1071. Next step: analyst review and corroboration with internal telemetry.

| `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | hash | 90 | high | Yes |

**Evidence:** demo_feed_alpha (malware), demo_feed_beta (malware)
**Reasons:** Listed in at least one local feed (+20); Listed by 2 or more independent feed files (+25); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1587 Develop Capabilities
**Analyst note:** Evidence: 2 local feed match(es). ATT&CK mappings: T1587. Next step: analyst review and corroboration with internal telemetry.

| `evil-login[.]example` | domain | 90 | high | Yes |

**Evidence:** demo_feed_alpha (phishing), demo_feed_beta (phishing)
**Reasons:** Listed in at least one local feed (+20); Listed by 2 or more independent feed files (+25); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1566 Phishing
**Analyst note:** Evidence: 2 local feed match(es). ATT&CK mappings: T1566. Next step: analyst review and corroboration with internal telemetry.

| `cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc` | hash | 65 | medium | Yes |

**Evidence:** demo_feed_alpha (ransomware)
**Reasons:** Listed in at least one local feed (+20); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1486 Data Encrypted for Impact
**Analyst note:** Evidence: 1 local feed match(es). ATT&CK mappings: T1486. Next step: analyst review and corroboration with internal telemetry.

| `dddddddddddddddddddddddddddddddddddddddd` | hash | 65 | medium | Yes |

**Evidence:** demo_feed_beta (malware)
**Reasons:** Listed in at least one local feed (+20); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1587 Develop Capabilities
**Analyst note:** Evidence: 1 local feed match(es). ATT&CK mappings: T1587. Next step: analyst review and corroboration with internal telemetry.

| `eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` | hash | 65 | medium | Yes |

**Evidence:** demo_feed_gamma (ransomware)
**Reasons:** Listed in at least one local feed (+20); High-risk category present (+30); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1486 Data Encrypted for Impact
**Analyst note:** Evidence: 1 local feed match(es). ATT&CK mappings: T1486. Next step: analyst review and corroboration with internal telemetry.

| `192[.]0[.]2[.]30` | ip | 60 | medium | Yes |

**Evidence:** demo_feed_alpha (malware-download), demo_feed_beta (malware-download)
**Reasons:** Listed in at least one local feed (+20); Listed by 2 or more independent feed files (+25); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1105 Ingress Tool Transfer
**Analyst note:** Evidence: 2 local feed match(es). ATT&CK mappings: T1105. Next step: analyst review and corroboration with internal telemetry.

| `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` | hash | 60 | medium | Yes |

**Evidence:** demo_feed_alpha (credential-theft), demo_feed_gamma (credential-theft)
**Reasons:** Listed in at least one local feed (+20); Listed by 2 or more independent feed files (+25); At least one listing is 30 days old or newer (+15)
**ATT&CK:** T1056 Input Capture
**Analyst note:** Evidence: 2 local feed match(es). ATT&CK mappings: T1056. Next step: analyst review and corroboration with internal telemetry.

| `bad-update[.]example` | domain | 20 | low | No |

**Evidence:** demo_feed_alpha (malware-download)
**Reasons:** Listed in at least one local feed (+20)
**ATT&CK:** T1105 Ingress Tool Transfer
**Analyst note:** Evidence: 1 local feed match(es). ATT&CK mappings: T1105. Next step: analyst review and corroboration with internal telemetry.

| `1[.]1[.]1[.]1` | ip | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `2606[:]4700[:]4700[:][:]1111` | ip | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `8[.]8[.]8[.]8` | ip | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `9[.]9[.]9[.]9` | ip | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `clean-example[.]com` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `cloudflare[.]com` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `example[.]org` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `github[.]com` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `iana[.]org` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `openai[.]com` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `www[.]ibm[.]com` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `www[.]microsoft[.]com` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `www[.]python[.]org` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.

| `www[.]wikipedia[.]org` | domain | 0 | low | Yes |

**Evidence:** No local feed match
**Reasons:** No local blocklist matches
**ATT&CK:** No mapping
**Analyst note:** Insufficient evidence: no local feed match. Validate using approved internal telemetry.
