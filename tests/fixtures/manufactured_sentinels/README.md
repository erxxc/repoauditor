# Manufactured falsification sentinels

These four tiny cases are method-of-manufactured-solutions controls for the falsification
instrument: two known exploitable paths and two close negative controls. The manifest is
outside `snapshot/`, so the model cannot retrieve the answer key.
Positive and negative controls use the same neutral candidate title within each mechanism,
so title wording does not disclose the disposition.
Each control is registered as a Flask route so HTTP reachability is part of the fixture's
checkable evidence rather than an assumption inferred from use of the request object.
The SSRF negative maps an untrusted page identifier to a fixed URL and disables redirects;
it does not treat initial-host validation alone as a complete SSRF control.

They are not normal benchmark repositories, are not ingested into customer scans, and must
never be reported as real-world precision or recall. A passing run only shows that the
configured instrument recovered these fixed known answers at that time.
