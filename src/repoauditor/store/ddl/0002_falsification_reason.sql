-- Migration 0002 — record why the falsification pass reached its verdict.
--
-- The falsify stage must never silently drop a candidate: killed findings are
-- persisted with their status AND the reason they were killed (null-result
-- logging). This column holds that reason for every verdict (confirmed / killed /
-- unresolved), so nothing about a finding's fate is lost.

ALTER TABLE finding ADD COLUMN falsification_reason TEXT;
