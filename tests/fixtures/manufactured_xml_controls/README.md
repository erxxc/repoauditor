# Manufactured XML representation controls

These two tiny Ruby shapes qualify one detection obligation: security validation performed
on one parsed XML representation while protected data is consumed from another, versus
consumption from the exact representation returned by verification.

The answer key is `manifest.json`, outside `snapshot/`. These controls do not execute XML,
prove a real parser differential, validate cryptography, or estimate real-world accuracy.
