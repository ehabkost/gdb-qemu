#!/bin/bash

set -e

MYDIR="$(realpath $(dirname "$0"))"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cd "$tmpdir"

check_expected() {
    "${MYDIR}/compat_checker.py" "$@" > OUTPUT
    diff -u EXPECTED OUTPUT
}


# no conflict:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > EXPECTED <<EOF
EOF

check_expected -q F1 F2

# simple compat_props conflict:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"Y"}]}}]
EOF
cat > EXPECTED <<EOF
ERROR: F1 vs F2: machine M: difference at mydev.myprop (u'X' != u'Y')
EOF

check_expected -q F1 F2

# no conflict when setting property twice:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"Y"},
                            {"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > EXPECTED <<EOF
EOF

check_expected -q F1 F2

# warning when setting property twice to the same value:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"},
                            {"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > EXPECTED <<EOF
WARNING: F1:M: duplicate compat property: mydev.myprop=X
EOF

check_expected -q F1 F2

