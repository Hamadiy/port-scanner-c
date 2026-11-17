#!/bin/sh
# Integration tests: open a local TCP listener and check that it is detected.
set -u

SCAN=./bin/portscan
OPEN_PORT=18080
WORK=$(mktemp -d)
pass=0
fail=0

python3 -m http.server "$OPEN_PORT" --bind 127.0.0.1 > /dev/null 2>&1 &
LISTENER=$!
trap 'kill "$LISTENER" 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 1

ok() { echo "  [PASS] $1"; pass=$((pass + 1)); }
ko() { echo "  [FAIL] $1"; fail=$((fail + 1)); }

echo "Running port scanner tests"

"$SCAN" -p 18079-18081 -t 500 -a 127.0.0.1 > "$WORK/out.txt"
cat "$WORK/out.txt"

if grep -Eq "^${OPEN_PORT} +open" "$WORK/out.txt"; then ok "listening port is open"; else ko "listening port is open"; fi
if grep -Eq "^18079 +closed" "$WORK/out.txt"; then ok "unused port is closed"; else ko "unused port is closed"; fi
if grep -q "1 open, 2 closed, 0 filtered" "$WORK/out.txt"; then ok "summary is correct"; else ko "summary is correct"; fi

"$SCAN" -p 22,80,18080,22 -t 500 127.0.0.1 > "$WORK/list.txt"
if grep -q "3 port(s)" "$WORK/list.txt"; then ok "duplicate ports are merged"; else ko "duplicate ports are merged"; fi

for bad in "0" "70000" "100-10" "abc" "1-" ","; do
    if "$SCAN" -p "$bad" 127.0.0.1 > /dev/null 2>&1; then ko "rejects port spec '$bad'"; else ok "rejects port spec '$bad'"; fi
done

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
