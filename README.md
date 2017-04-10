# gdb-qemu

Scripts to extract data from a QEMU binary and compare machine-
type compatibility between different QEMU binaries.

## Collecting JSON dumps

To collect data from a single QEMU binary and save it in a JSON
dump, use the `-O` option. e.g.:

    $ ./compat_checker.py --qemu /usr/bin/qemu-system-x86_64 --all-devices -O qemu-raw-data.json

## Comparing binaries and/or JSON dumps

### Comparing multiple JSON dumps

After you collected data from different QEMU versions, you can
compare all machine-types in it using multiple `--raw-file`
options:

    $ ./compat_checker.py --raw-file dump1.json --raw-file dump2.json

### Comparing multiple QEMU binaries

Multiple QEMU binaries can be compared, too:

    $ ./compat_checker.py --qemu ./build1/qemu-system-x86_64 --qemu ./build2/qemu-system-x86_64

### Comparing QEMU binaries and JSOn dumps:

`--raw-file` can be combined with `--qemu`, to compare data from
a QEMU binary with a JSON dump:

    $ ./compat_checker.py --raw-file dump-from-another-host.json --qemu /usr/bin/qemu-system-x86_64


## Testing the low-level GDB script

If you want to test the `extract-qemu-info.py` gdb script, run
the script using `gdb -P`. e.g.:

    $ gdb -q -P extract-qemu-info.py ~/rh/proj/virt/qemu/x86-kvm-build/x86_64-softmmu/qemu-system-x86_64 --device x86_64-cpu --machine pc
    [{"result": {"fw_name": null, "vmsd": null, "unrealize": "0x555555686125 <device_unrealize>", "reset": null, "unplug": null, "realize": "0x555555869867 <x86_cpu_realizefn>", "exit": null, "cannot_instantiate_with_device_add_yet": true, "props": [{"arrayoffset": 0, "qtype": 6, "arrayfieldsize": 0, "name": "pmu", "info": {"enum_table": null, "parse": null, "print": null, "release": null, "legacy_name": null, "name": "boolean"}, "bitnr": 0, "arrayinfo": null, "offset": 69576, "defval": false}, {"arrayoffset": 0, "qtype": 0, "arrayfieldsize": 0, "name": "hv-spinlocks", "info": {"enum_table": null, "parse": null, "print": null, "release": null, "legacy_name": null, "name": "int"}, "bitnr": 0, "arrayinfo": null, "offset": 0}, {"arrayoffset": 0, "qtype": 6, "arrayfieldsize": 0, "name": "hv-relaxed", "info": {"enum_table": null, "parse": null, "print": null, "release": null, "legacy_name": null, "name": "boolean"}, "bitnr": 0, "arrayinfo": null, "offset": 69521, "defval": false}, {"arrayoffset": 0, "qtype": 6, "arrayfieldsize": 0, "name": "hv-vapic", "info": {"enum_table": null, "parse": null, "print": null, "release": null, "legacy_name": null, "name": "boolean"}, "bitnr": 0, "arrayinfo": null, "offset": 69520, "defval": false}, {"arrayoffset": 0, "qtype": 6, "arrayfieldsize": 0, "name": "hv-time", "info": {"enum_table": null, "parse": null, "print": null, "release": null, "legacy_name": null, "name": "boolean"}, "bitnr": 0, "arrayinfo": null, "offset": 69528, "defval": false}, {"arrayoffset": 0, "qtype": 6, "arrayfieldsize": 0, "name": "check", "info": {"enum_table": null, "parse": null, "print": null, "release": null, "legacy_name": null, "name": "boolean"}, "bitnr": 0, "arrayinfo": null, "offset": 69529, "defval": false}, {"arrayoffset": 0, "qtype": 6, "arrayfieldsize": 0, "name": "enforce", "info": {"enum_table": null, "parse": null, "print": null, "release": null, "legacy_name": null, "name": "boolean"}, "bitnr": 0, "arrayinfo": null, "offset": 69530, "defval": false}], "bus_type": "icc-bus", "init": null, "desc": null}, "request": ["query-device-type", "x86_64-cpu"]}, {"result": {"boot_order": "cad", "no_parallel": 0, "default_machine_opts": "firmware=bios-256k.bin", "use_virtcon": 0, "desc": "RHEL 7.0.0 PC (i440FX + PIIX, 1996)", "no_cdrom": 0, "max_cpus": 240, "no_floppy": 0, "no_sdcard": 0, "reset": null, "name": "pc-i440fx-rhel7.0.0", "no_serial": 0, "is_default": 1, "alias": "pc", "use_sclp": 0, "hw_version": null, "compat_props": []}, "request": ["query-machine", "pc"]}]
    $ 
