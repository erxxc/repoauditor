# Optimization governance

I. Purpose

   A. This directory contains improvements that are valuable but not required by the
      current POC Definition of Done.
   B. It prevents tuning, polish, and research work from silently becoming MVP scope.

II. Intake rule

   A. Add every proposed non-MVP change to
      [`optimization-register.md`](optimization-register.md) before implementation.
   B. Record its source, owner, status, rationale, activation evidence, and relationship to
      the current DoD.
   C. Default status is `deferred`; enthusiasm is not an activation gate.

III. Promotion rule

   A. An optimization may be implemented when its evidence gate is satisfied and it does not
      displace an open MVP item.
   B. It becomes MVP-required only after explicit project-owner approval updates both
      `../poc-definition-of-done.md` and `../poc-recovery-plan.md`.
   C. Completed optimization work remains valid even when it was not necessary for the POC.

IV. Required entry shape

   A. Identifier and title.
   B. Date and source.
   C. Status and proposed owner.
   D. Benefit and non-goal.
   E. Activation gate or prerequisite.
   F. DoD impact: none, proposed revision, or approved revision.
   G. Links to supporting evidence and resulting PRs/runs.
   H. Use [`TEMPLATE.md`](TEMPLATE.md) when an item needs more detail than one register entry.
