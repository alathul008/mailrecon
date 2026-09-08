# Risk Model

MailRecon's score is an explainable prioritization signal, not a probability of compromise and not an identity verdict.

## Dimensions

| Dimension | Weight | Meaning |
|---|---:|---|
| Identity exposure | 30% | Signals associated with the email identity and local-part |
| Breach exposure | 35% | Observed breach/exposure signals from configured providers |
| Domain security | 20% | Defensive posture signals such as SPF/DMARC/DNSSEC |
| Public footprint | 15% | Public-profile and username correlation signals |

Each dimension is bounded to 0–100 before weighting. Provider failures are not converted into clean findings.

## Interpretation

- **LOW**: 0–24
- **MEDIUM**: 25–49
- **HIGH**: 50–74
- **CRITICAL**: 75–100

A score should always be interpreted alongside its underlying findings, provider states and confidence values.
