#!/bin/bash

##############################################################################
# Proxmox Backup Server Restore Script
# For dedicated server backups (host backups only)
##############################################################################

# Default configuration
PBS_REPOSITORY="${PBS_REPOSITORY:-}"
PBS_PASSWORD="${PBS_PASSWORD:-}"
BACKUP_ID="${BACKUP_ID:-}"
SNAPSHOT="${SNAPSHOT:-}"
MOUNT_PATH="${MOUNT_PATH:-/home/pixibixi/pbs-backup}"
CONFIG_FILE="${CONFIG_FILE:-}"

# Colors for logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
#
# Global variables for backup parsing
declare -g SNAPSHOTS_CACHE=""
declare -g BACKUP_TYPE=""
declare -g BACKUP_NAME=""


log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_note() {
    echo -e "${BLUE}[NOTE]${NC} $*"
}

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Mount or restore a dedicated server backup from Proxmox Backup Server.

Options:
    -c, --config FILE         Configuration file (default: searches in order:
                              ./pbs-restore.conf, ~/.config/pbs-restore.conf, /etc/pbs-restore.conf)
    -r, --repository REPO     PBS repository (format: [user@pbs@]host[:port]:datastore)
                              Example: root@pam@pbs.example.com:8007:backup-store
    -b, --backup-id ID        Backup ID (ex: host/hostname or just hostname)
    -s, --snapshot SNAP       Snapshot to use (format: YYYY-MM-DDTHH:MM:SSZ or timestamp)
                              Use "latest" for the most recent snapshot
    -m, --mount-path PATH     Mount point for the backup (default: /mnt/pbs-backup)
    -l, --list                List available snapshots
    --list-files              List files/directories available in the snapshot
    --mount                   Mount the backup (default action)
    --umount                  Unmount the backup
    -h, --help                Display this help

Environment variables and configuration file:
    PBS_REPOSITORY            PBS repository
    PBS_PASSWORD              PBS password
    PBS_FINGERPRINT           PBS SSL fingerprint (optional)
    BACKUP_ID                 Default backup ID
    MOUNT_PATH                Default mount path

Configuration file format:
    # Comments are supported
    PBS_REPOSITORY=root@pam@pbs.example.com:8007:backup-store
    PBS_PASSWORD=your-secure-password
    PBS_FINGERPRINT=xx:xx:xx:...
    BACKUP_ID=host/myserver
    MOUNT_PATH=/mnt/pbs-backup

Priority order (highest to lowest):
    1. Command line arguments
    2. Environment variables
    3. Configuration file

Examples:
    # Mount latest snapshot (default mount point)
    $0 -b host/server-prod -s latest --mount

    # Mount to custom location
    $0 -b host/server-prod -s latest --mount-path /mnt/mybackup --mount

    # Mount specific snapshot
    $0 -b host/server-prod -s 2026-02-13T15:28:47Z --mount

    # List snapshots
    $0 -b host/server-prod -l

    # Unmount
    $0 --umount

    # After mounting, access files directly:
    # ls /mnt/pbs-backup/etc/nginx
    # cp /mnt/pbs-backup/home/user/file.pdf /tmp/
    # rsync -av /mnt/pbs-backup/etc/nginx/ /etc/nginx/

EOF
    exit 0
}

load_config_file() {
    local config_file="$1"

    [[ ! -f "$config_file" ]] && {
        log_error "Configuration file not found: ${config_file}"
        exit 1
    }

    log_info "Loading configuration from: ${config_file}"

    local line key value
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        if [[ "$line" =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*(.+)[[:space:]]*$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"

            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"

            case "$key" in
                PBS_REPOSITORY)     [[ -z "$PBS_REPOSITORY" ]] && PBS_REPOSITORY="$value" ;;
                PBS_PASSWORD)       [[ -z "$PBS_PASSWORD" ]] && PBS_PASSWORD="$value" ;;
                PBS_FINGERPRINT)    [[ -z "$PBS_FINGERPRINT" ]] && PBS_FINGERPRINT="$value" ;;
                BACKUP_ID)          [[ -z "$BACKUP_ID" ]] && BACKUP_ID="$value" ;;
                MOUNT_PATH)         [[ "$MOUNT_PATH" == "/mnt/pbs-backup" ]] && MOUNT_PATH="$value" ;;
            esac
        fi
    done < "$config_file"

    log_info "Configuration loaded"
}

find_config_file() {
    local location
    for location in "./pbs-restore.conf" "${HOME}/.config/pbs-restore.conf" "/etc/pbs-restore.conf"; do
        [[ -f "$location" ]] && { echo "$location"; return 0; }
    done
    return 1
}

check_dependencies() {
    log_info "Checking dependencies..."

    command -v proxmox-backup-client &>/dev/null || {
        log_error "proxmox-backup-client is not installed"
        log_info "Installation: apt install proxmox-backup-client"
        exit 1
    }

    command -v jq &>/dev/null || {
        log_error "jq is not installed"
        log_info "Installation: apt install jq"
        exit 1
    }

    command -v fusermount &>/dev/null || command -v fusermount3 &>/dev/null || {
        log_error "fuse is not installed (required for mounting)"
        log_info "Installation: apt install fuse3"
        exit 1
    }

    log_info "Dependencies OK"
}


parse_backup_id() {
    if [[ "$BACKUP_ID" =~ ^host/(.+)$ ]]; then
        BACKUP_TYPE="host"
        BACKUP_NAME="${BASH_REMATCH[1]}"
    elif [[ "$BACKUP_ID" =~ ^(.+)/(.+)$ ]]; then
        BACKUP_TYPE="${BASH_REMATCH[1]}"
        BACKUP_NAME="${BASH_REMATCH[2]}"
    else
        BACKUP_TYPE="host"
        BACKUP_NAME="$BACKUP_ID"
        BACKUP_ID="host/${BACKUP_NAME}"
    fi
}

validate_backup_id() {
    parse_backup_id

    [[ "$BACKUP_TYPE" != "host" ]] && {
        log_error "This script only supports host backups (format: host/hostname)"
        log_error "Provided backup ID: ${BACKUP_ID}"
        exit 1
    }
}

get_snapshots_list() {
    if [[ -z "$SNAPSHOTS_CACHE" ]]; then
        export PBS_REPOSITORY PBS_PASSWORD
        SNAPSHOTS_CACHE=$(proxmox-backup-client snapshot list --output-format json 2>/dev/null) || {
            log_error "Failed to retrieve snapshots list"
            exit 1
        }
    fi
    echo "$SNAPSHOTS_CACHE"
}

list_snapshots() {
    log_info "Snapshots list for ${BACKUP_ID}..."
    proxmox-backup-client snapshot list 2>/dev/null
}

list_snapshot_files() {
    local snapshot_time="$1"

    log_info "Snapshot content ${BACKUP_ID}/${snapshot_time}..."

    export PBS_REPOSITORY PBS_PASSWORD

    log_info "Available archives:"
    proxmox-backup-client snapshot files "${BACKUP_ID}/${snapshot_time}" 2>/dev/null || true
}

get_latest_snapshot() {
    log_info "Searching for latest snapshot for ${BACKUP_ID}..." >&2

    local latest_ts latest_iso
    latest_ts=$(get_snapshots_list | jq -r ".[] | select(.\"backup-id\" == \"${BACKUP_NAME}\" and .\"backup-type\" == \"${BACKUP_TYPE}\") | .\"backup-time\"" | sort -r | head -n1)

    [[ -z "$latest_ts" ]] && {
        log_error "No snapshot found for ${BACKUP_ID}" >&2
        log_info "Available backups:" >&2
        get_snapshots_list | jq -r '.[] | "\(.["backup-type"])/\(.["backup-id"])"' | sort -u >&2
        exit 1
    }

    # Convert Unix timestamp to ISO 8601 format
    latest_iso=$(date -u -d "@${latest_ts}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "${latest_ts}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)

    echo "$latest_iso"
}

mount_backup() {
    local snapshot_time="$1"

    log_info "Preparing to mount backup..."
    log_info "  Repository: ${PBS_REPOSITORY}"
    log_info "  Backup ID: ${BACKUP_ID}"
    log_info "  Snapshot: ${snapshot_time}"
    log_info "  Mount point: ${MOUNT_PATH}"

    if mountpoint -q "${MOUNT_PATH}" 2>/dev/null; then
        log_warn "Mount point ${MOUNT_PATH} is already mounted"
        log_info "Use --umount to unmount first, or choose a different mount point"
        exit 1
    fi

    if [[ ! -d "${MOUNT_PATH}" ]]; then
        log_info "Creating mount point: ${MOUNT_PATH}"
        mkdir -p "${MOUNT_PATH}" || {
            log_error "Failed to create mount point"
            exit 1
        }
    fi

    export PBS_REPOSITORY PBS_PASSWORD

    log_info "Mounting backup (this may take a moment)..."

    if proxmox-backup-client mount \
        "${BACKUP_ID}/${snapshot_time}" \
        "root.pxar.didx" \
        "${MOUNT_PATH}" 2>/dev/null; then

        log_info "✓ Backup mounted successfully!"
        echo ""
        log_note "==================================================================="
        log_note "Backup is now accessible at: ${MOUNT_PATH}"
        log_note ""
        log_note "Examples:"
        log_note "  # List files"
        log_note "  ls ${MOUNT_PATH}/etc/nginx"
        log_note ""
        log_note "  # Copy a file"
        log_note "  cp ${MOUNT_PATH}/home/user/file.pdf /tmp/"
        log_note ""
        log_note "  # Restore a directory"
        log_note "  rsync -av ${MOUNT_PATH}/etc/nginx/ /etc/nginx/"
        log_note ""
        log_note "To unmount when done:"
        log_note "  $0 --umount --mount-path ${MOUNT_PATH}"
        log_note "  or: fusermount -u ${MOUNT_PATH}"
        log_note "==================================================================="
    else
        log_error "Failed to mount backup"
        exit 1
    fi
}

umount_backup() {
    local mount_point="${MOUNT_PATH}"

    log_info "Unmounting ${mount_point}..."

    if ! mountpoint -q "${mount_point}" 2>/dev/null; then
        log_warn "Mount point ${mount_point} is not mounted"
        return 0
    fi

    if command -v fusermount &>/dev/null; then
        fusermount -u "${mount_point}" && {
            log_info "✓ Backup unmounted successfully"
            return 0
        }
    fi

    if command -v fusermount3 &>/dev/null; then
        fusermount3 -u "${mount_point}" && {
            log_info "✓ Backup unmounted successfully"
            return 0
        }
    fi

    log_error "Failed to unmount ${mount_point}"
    log_info "Try manually: fusermount -u ${mount_point}"
    exit 1
}

# Parse arguments
LIST_MODE=false
LIST_FILES_MODE=false
MOUNT_MODE=false
UMOUNT_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)        CONFIG_FILE="$2"; shift 2 ;;
        -r|--repository)    PBS_REPOSITORY="$2"; shift 2 ;;
        -b|--backup-id)     BACKUP_ID="$2"; shift 2 ;;
        -s|--snapshot)      SNAPSHOT="$2"; shift 2 ;;
        -m|--mount-path)    MOUNT_PATH="$2"; shift 2 ;;
        -l|--list)          LIST_MODE=true; shift ;;
        --list-files)       LIST_FILES_MODE=true; shift ;;
        --mount)            MOUNT_MODE=true; shift ;;
        --umount|--unmount) UMOUNT_MODE=true; shift ;;
        -h|--help)          usage ;;
        *)                  log_error "Unknown option: $1"; usage ;;
    esac
done

# Handle unmount first (doesn't need other parameters)
if [[ "$UMOUNT_MODE" == true ]]; then
    umount_backup
    exit 0
fi

# Load configuration file
if [[ -n "$CONFIG_FILE" ]]; then
    load_config_file "$CONFIG_FILE"
elif default_config=$(find_config_file); then
    log_info "Configuration file found: ${default_config}"
    load_config_file "$default_config"
else
    log_warn "No configuration file found"
fi

# Validate required parameters
[[ -z "$PBS_REPOSITORY" ]] && {
    log_error "PBS repository is required (-r, PBS_REPOSITORY or config file)"
    usage
}

[[ -z "$BACKUP_ID" ]] && {
    log_error "Backup ID is required (-b, BACKUP_ID or config file)"
    usage
}

validate_backup_id

[[ -z "$PBS_PASSWORD" ]] && {
    log_warn "PBS_PASSWORD is not set"
    read -sp "PBS password: " PBS_PASSWORD
    echo
}

export PBS_PASSWORD

# Execution
check_dependencies

[[ "$LIST_MODE" == true ]] && { list_snapshots; exit 0; }

# For mount and list-files, we need a snapshot
if [[ "$MOUNT_MODE" == true ]] || [[ "$LIST_FILES_MODE" == true ]]; then
    [[ -z "$SNAPSHOT" ]] && {
        log_error "Snapshot is required (-s or SNAPSHOT)"
        usage
    }

    [[ "$SNAPSHOT" == "latest" ]] && {
        SNAPSHOT=$(get_latest_snapshot)
        log_info "Latest snapshot found: ${SNAPSHOT}"
    }
fi

[[ "$LIST_FILES_MODE" == true ]] && { list_snapshot_files "$SNAPSHOT"; exit 0; }

# Default action is mount if no other action specified
if [[ "$MOUNT_MODE" == false ]] && [[ "$LIST_MODE" == false ]] && [[ "$LIST_FILES_MODE" == false ]] && [[ "$UMOUNT_MODE" == false ]]; then
    MOUNT_MODE=true
    log_info "No action specified, defaulting to mount"
fi

if [[ "$MOUNT_MODE" == true ]]; then
    [[ -z "$SNAPSHOT" ]] && {
        log_error "Snapshot is required for mount operation (-s or SNAPSHOT)"
        usage
    }

    mount_backup "$SNAPSHOT"
fi

log_info "Script completed"
