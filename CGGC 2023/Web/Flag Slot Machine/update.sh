#!/bin/bash

DB_USER="root"
DB_NAME="secret_db"
TABLE_NAME="s3cret_table"
COLUMN_NAME="secret"
NEW_VALUE=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | xxd -p -c 16)

mysql --user=$DB_USER $DB_NAME <<EOF
UPDATE $TABLE_NAME SET $COLUMN_NAME='$NEW_VALUE';
EOF

echo "done"
