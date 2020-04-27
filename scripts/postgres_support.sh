#!/bin/bash
set -e
POSTGRES=$1
echo "Postgres support : ${POSTGRES}"
if [ "$POSTGRES" == True ]; then
 pip3 install psycopg2-binary
 #Enable postgres support
 sed -i '/# Sqlite3 suport/,/# End Sqlite3 support/d' ../Kensa/settings.py && \
 sed -i "/# Postgres DB - Install psycopg2/,/'''/d" ../Kensa/settings.py && \
 sed -i "/# End Postgres support/,/'''/d" ../Kensa/settings.py && \
 sed -i "s/'PASSWORD': '',/'PASSWORD': 'password',/" ../Kensa/settings.py && \
 sed -i "s/'HOST': 'localhost',/'HOST': 'postgres',/" ../Kensa/settings.py
fi
