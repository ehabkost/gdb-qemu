#!/bin/bash
# Wrapper to validate a given QEMU binary/dump against reference dumps
ARGS=("$@")

FAILURES=0

validate() {
    ./compat_checker.py "$@" "${ARGS[@]}"
}

#TODO: detect failures/warnings and return appropriate exit code
#TODO: avoid warnings if machine-type is missing on the file being validated

validate -M pc-i440fx-2.10 reference-dumps/v2.10.0-x86_64.json
validate -M pc-i440fx-2.9 reference-dumps/v2.9.0-x86_64.json
#validate -M pc-i440fx-2.8 reference-dumps/v2.8.0-x86_64.json
#validate -M pc-i440fx-2.7 reference-dumps/v2.7.0-x86_64.json
validate -M pc-i440fx-2.6 reference-dumps/v2.6.0-x86_64.json
#validate -M pc-i440fx-2.5 reference-dumps/v2.5.0-x86_64.json
#validate -M pc-i440fx-2.4 reference-dumps/v2.4.0-x86_64.json
validate -M pc-i440fx-2.3 reference-dumps/v2.3.0-x86_64.json
#validate -M pc-i440fx-2.1 reference-dumps/v2.1.0-x86_64.json
#validate -M pc-i440fx-2.0 reference-dumps/v2.0.0-x86_64.json

validate -M pc-i440fx-rhel7.0.0 reference-dumps/qemu-kvm-1.5.3-60.el7.x86_64.json
validate -M pc-i440fx-rhel7.1.0 reference-dumps/qemu-kvm-rhev-2.1.2-23.el7.x86_64.json
validate -M pc-i440fx-rhel7.2.0 reference-dumps/qemu-kvm-rhev-2.3.0-31.el7.x86_64.json
validate -M pc-i440fx-rhel7.3.0 reference-dumps/qemu-kvm-rhev-2.6.0-27.el7.x86_64.json
validate -M pc-i440fx-rhel7.4.0 reference-dumps/qemu-kvm-rhev-2.9.0-14.el7.x86_64.json
