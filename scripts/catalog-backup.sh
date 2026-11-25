#!/bin/sh
# Run in the PostgreSQL client container with a private, persistent mount.
set -eu
umask 077
cd "${CATALOG_BACKUP_DIR:?missing persistent backup mount}"

archive() {
    file=$1
    connection=$2
    if [ ! -f "$file" ]; then
        pg_dump --dbname="$connection" --format=custom --file="$file.partial"
        pg_restore --file=/dev/null "$file.partial"
        mv "$file.partial" "$file"
    else
        pg_restore --file=/dev/null "$file"
    fi
}

case "${1:-}" in
    backup)
        archive web.dump "${DATABASE_URL:?missing runtime database connection}"
        archive engine.dump "${INTERNAL_DATABASE_URL:?missing internal database connection}"
        ;;
    verify)
        pg_restore --file=/dev/null web.dump
        pg_restore --file=/dev/null engine.dump
        ;;
    cleanup)
        rm -f -- web.dump engine.dump web.dump.partial engine.dump.partial drained drained.tmp
        ;;
    *)
        echo 'Expected backup or cleanup' >&2
        exit 2
        ;;
esac
