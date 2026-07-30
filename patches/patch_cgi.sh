#!/bin/bash
# Patch hostpython: copy cgi_stub.py to hostpython's stdlib as cgi.py
# Python 3.13+ removed the 'cgi' module which Cython 0.29.x needs

HOSTPYTHON=$(find .buildozer -path "*/hostpython3/*" -name "python" -type f 2>/dev/null | head -1)
if [ -z "$HOSTPYTHON" ]; then
    echo "ERROR: hostpython not found"
    exit 1
fi

echo "hostpython: $HOSTPYTHON"
"$HOSTPYTHON" --version

STDLIB=$("$HOSTPYTHON" -c "import sysconfig; print(sysconfig.get_path('stdlib'))" 2>/dev/null)
if [ -z "$STDLIB" ] || [ ! -d "$STDLIB" ]; then
    echo "ERROR: stdlib not found"
    exit 1
fi

cp cgi_stub.py "$STDLIB/cgi.py"
echo "Patched: $STDLIB/cgi.py"
"$HOSTPYTHON" -c "import cgi; print('cgi module OK')"
