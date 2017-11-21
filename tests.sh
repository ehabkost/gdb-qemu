#!/bin/bash

set -e

MYDIR="$(realpath $(dirname "$0"))"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cd "$tmpdir"

check_expected() {
    local testname="$1"
    shift
    echo "Checking: $testname"
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

check_expected simple_no_conflict -q F1 F2

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

check_expected simple_conflict -q F1 F2

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

check_expected twice_diff_value -q F1 F2

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

check_expected twice_same_value -q F1 F2


# warning when we don't know anything about a property:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[]}},
 {"request":["device-type", "mydev"],
  "result":{}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > EXPECTED <<EOF
WARNING: I don't know the default value of mydev.myprop in F1 (machine M)
EOF

check_expected unknown_defvalue -q F1 F2


# error when we do have the property list but the property doesn't exist:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"off"}]}},
 {"request":["device-type", "mydev"],
  "result":{"props":[{"name":"myprop", "defval":true,
                      "info":{"name":"bool"}}],
            "instance_props":[]}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"off"}]}},
 {"request":["device-type", "mydev"],
  "result":{"props":[{"name":"anotherprop", "defval":true,
                      "info":{"name":"bool"}}],
            "instance_props":[]}}]
EOF
cat > EXPECTED <<EOF
ERROR: Invalid property: mydev.myprop at F2:M
EOF

check_expected invalid_prop -q F1 F2



# no warning when the device type is not compiled in:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"off"}]}},
 {"request":["device-type", "mydev"],
  "result":{"props":[{"name":"myprop", "defval":true,
                      "info":{"name":"bool"}}]}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"off"}]}},
 {"request":["device-type", "mydev"],
  "result":{}}]
EOF
cat > EXPECTED <<EOF
WARNING: Not enough info to validate property: mydev.myprop at F2:M
EOF

check_expected no_prop_info -q F1 F2



# no conflict when we know the default value for the property:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[]}},
 {"request":["device-type", "mydev"],
  "result":{"props":[{"name":"myprop", "defval":"X",
                      "info":{"name":"string"}}]}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[{"driver":"mydev",
                             "property":"myprop",
                             "value":"X"}]}}]
EOF
cat > EXPECTED <<EOF
EOF

check_expected known_defvalue -q F1 F2


# warning when the default value conflicts with compat_props:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{"compat_props":[]}},
 {"request":["device-type", "mydev"],
  "result":{"props":[{"name":"myprop", "defval":"X",
                      "info":{"name":"string"}}]}}]
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

check_expected conflict_defvalue -q F1 F2



# warning when unexpected machine field is missing:

cat > F1 <<EOF
[{"request":["machine", "M"],
  "result":{}}]
EOF
cat > F2 <<EOF
[{"request":["machine", "M"],
  "result":{"some_field": "X"}}]
EOF
cat > EXPECTED <<EOF
WARNING: F1: I don't know how to deal with missing machine.some_field field in machine M
EOF

check_expected unknown_machine_field -q F1 F2


#PLANNED:
# warning when a device type vanishes and is not supported anymore:
#
# cat > F1 <<EOF
# [{"request":["machine", "M"],
#   "result":{},
#  {"request":["device-type", "mydev"],
#   "result":{"props":[{"name":"myprop", "defval":true,
#                       "info":{"name":"bool"}}]}}]
# EOF
# cat > F2 <<EOF
# [{"request":["machine", "M"],
#   "result":{},
#  {"request":["device-type", "anotherdev"],
#   "result":{"props":[{"name":"anotherprop", "defval":true,
#                       "info":{"name":"bool"}}]}}]
# EOF
# cat > EXPECTED <<EOF
# WARN: device type mydev is not available anymore
# EOF
#
# check_expected device_type_removed -q F1 F2
