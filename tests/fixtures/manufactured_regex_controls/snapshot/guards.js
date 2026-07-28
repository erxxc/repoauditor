function vulnerableGuard(next) {
  return /^\s*protocol(.[a-z]+)?.allow/.test(next);
}

function fixedGuard(next) {
  return /^\s*protocol(.[a-z]+)?.allow/i.test(next);
}
