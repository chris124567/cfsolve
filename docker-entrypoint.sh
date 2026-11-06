#!/bin/sh
set -e

if [ -n "${PORT}" ]; then
    LISTEN="0.0.0.0:${PORT}"
else
    LISTEN="${LISTEN:-0.0.0.0:8742}"
fi
FINGERPRINT="${FINGERPRINT:-profiles/safari-26-ios.json}"
CONCURRENCY="${CONCURRENCY:-auto}"

# If no arguments passed, launch using environment variables
if [ "$#" -eq 0 ]; then
    CMD="server --listen ${LISTEN} --fingerprint ${FINGERPRINT}"
    # `auto` uses the container's available CPUs. On Heroku Standard-1X that is
    # 1; overriding it to 150 makes every request miss the 30s router timeout.
    if [ -n "${CONCURRENCY}" ] && [ "${CONCURRENCY}" != "auto" ]; then
        CMD="${CMD} --concurrency ${CONCURRENCY}"
    fi
    if [ -n "${PROXY}" ]; then
        CMD="${CMD} --proxy ${PROXY}"
    fi
    exec ${CMD}
fi

# If first argument starts with a dash (e.g. -c or --concurrency), invoke server with default listen
if [ "${1#-}" != "$1" ]; then
    # Check if --listen was explicitly passed in arguments
    case " $* " in
        *" --listen "*|*" -l "*)
            exec server "$@"
            ;;
        *)
            exec server --listen "${LISTEN}" "$@"
            ;;
    esac
fi

# Otherwise execute custom command directly
exec "$@"
