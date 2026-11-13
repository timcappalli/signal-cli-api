#!/usr/bin/env bash
# Helper script to perform Signal account registration/linking via terminal inside the container
# This ensures zero sensitive account details are exposed via environment variables, ps, or shell history.

set -euo pipefail

CONTAINER_NAME="signal-api"

show_help() {
  cat <<EOF
Usage: ./register.sh <command> [arguments]

Commands:
  recovery <account_id> [extra_flags]    Register a numberless Signal account (prompts for recovery key via stdin)
  link [device_name]                     Link a secondary device via QR code (default: 'signal-api')
  register <account_id_or_phone> [args]  Register an account via SMS/voice (supports --captcha, --voice, etc.)
  verify <phone_number> <code>           Verify phone number registration with SMS code
  username <account_uuid> <name>         Set a Signal username for an account
  accounts                               List accounts registered in the container
  cli <arguments...>                     Run arbitrary signal-cli commands directly inside the container

Examples:
  # Interactively prompt for recovery key (keeps it out of ps and shell history):
  ./register.sh recovery "my-account-id"

  # Or pipe recovery key via stdin:
  printf '%s\n' "\$RECOVERY_KEY" | ./register.sh recovery "my-account-id"

  # Link secondary device via QR code:
  ./register.sh link "my-bot-device"

  # List existing accounts:
  ./register.sh accounts
EOF
}

if [ $# -eq 0 ]; then
  show_help
  exit 1
fi

CMD="$1"
shift

case "$CMD" in
  recovery|register-recovery)
    if [ $# -lt 1 ]; then
      echo "Error: Account ID required. Example: ./register.sh recovery <ACCOUNT_ID>"
      exit 1
    fi
    ACCOUNT_ID="$1"
    shift || true

    # Refuse positional recovery keys on the command line to prevent exposure in ps and shell history
    if [ $# -ge 1 ] && [[ "$1" != -* ]]; then
      echo "Error: Do not pass the recovery key as a command-line argument (it exposes the key in ps and shell history)." >&2
      echo "Run './register.sh recovery \"$ACCOUNT_ID\"' and enter the recovery key when prompted (or pipe it via stdin)." >&2
      exit 1
    fi

    if [ -t 0 ]; then
      echo -n "Enter Recovery Key for account '$ACCOUNT_ID': " >&2
      IFS= read -rs RECOVERY_KEY
      echo "" >&2
    else
      IFS= read -r RECOVERY_KEY
    fi

    if [ -z "$RECOVERY_KEY" ]; then
      echo "Error: Recovery key cannot be empty." >&2
      exit 1
    fi

    echo "Registering numberless account '$ACCOUNT_ID' using recovery key..."
    # Pass recovery key via stdin into /app/signal-api register-recovery (JSON-RPC over local socket/stdin)
    # so the recovery key never appears in host or container process argument lists (ps / /proc/<pid>/cmdline).
    printf '%s\n' "$RECOVERY_KEY" | docker compose exec -T "$CONTAINER_NAME" \
      /app/signal-api register-recovery "$ACCOUNT_ID" "$@"
    ;;

  link)
    DEVICE_NAME="${1:-signal-api}"
    echo "Generating Signal linking QR code inside '$CONTAINER_NAME'..."
    docker compose exec "$CONTAINER_NAME" signal-cli link -n "$DEVICE_NAME"
    ;;

  register)
    if [ $# -lt 1 ]; then
      echo "Error: Account ID or phone number required. Example: ./register.sh register <ACCOUNT_ID>"
      exit 1
    fi
    ACCOUNT="$1"
    shift
    for arg in "$@"; do
      if [[ "$arg" == "--recovery-key"* ]]; then
        echo "Error: Use './register.sh recovery <ACCOUNT_ID>' instead of passing --recovery-key on the command line." >&2
        exit 1
      fi
    done
    docker compose exec "$CONTAINER_NAME" signal-cli -a "$ACCOUNT" register "$@"
    ;;

  verify)
    if [ $# -lt 2 ]; then
      echo "Error: Phone number and verification code required. Example: ./register.sh verify +15551234567 123456"
      exit 1
    fi
    docker compose exec "$CONTAINER_NAME" signal-cli -a "$1" verify "$2"
    ;;

  username)
    if [ $# -lt 2 ]; then
      echo "Error: Account UUID and Username required. Example: ./register.sh username <UUID> <USERNAME>"
      exit 1
    fi
    docker compose exec "$CONTAINER_NAME" signal-cli -a "$1" updateAccount --username "$2"
    ;;

  accounts)
    docker compose exec "$CONTAINER_NAME" signal-cli listAccounts
    ;;

  cli)
    docker compose exec "$CONTAINER_NAME" signal-cli "$@"
    ;;

  help|-h|--help)
    show_help
    ;;

  *)
    echo "Unknown command: $CMD"
    show_help
    exit 1
    ;;
esac
