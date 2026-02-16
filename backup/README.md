# Proxmox Backup Server Restore Script

CLI tool to mount and restore dedicated server backups from Proxmox Backup Server (PBS).

## Features

- Mount PBS backups as read-only FUSE filesystem
- List available snapshots and backup content
- Interactive or config-driven authentication
- Support for host backups only (dedicated servers)

## Prerequisites

```bash
apt install proxmox-backup-client jq fuse3
```

## Installation

```bash
chmod +x restore-backup.sh
# Optional: symlink to PATH
ln -s $(pwd)/restore-backup.sh /usr/local/bin/pbs-restore
```

## Configuration

Create a config file at one of these locations (searched in order):

1. `./pbs-restore.conf` (project-local)
2. `~/.config/pbs-restore.conf` (user)
3. `/etc/pbs-restore.conf` (system-wide)

**Example config:**

```bash
PBS_REPOSITORY=root@pam@pbs.example.com:8007:backup-store
PBS_PASSWORD=your-secure-password
PBS_FINGERPRINT=xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
BACKUP_ID=host/myserver
MOUNT_PATH=/mnt/pbs-backup
```

**Priority order:** CLI args > env vars > config file

## Usage

### List available snapshots

```bash
./restore-backup.sh -b host/server-prod --list
```

### Mount latest snapshot

```bash
./restore-backup.sh -b host/server-prod -s latest --mount
```

### Mount specific snapshot

```bash
./restore-backup.sh -b host/server-prod -s 2026-02-13T15:28:47Z --mount
```

### Mount to custom path

```bash
./restore-backup.sh -b host/server-prod -s latest -m /mnt/mybackup --mount
```

### List snapshot content

```bash
./restore-backup.sh -b host/server-prod -s latest --list-files
```

### Unmount

```bash
./restore-backup.sh --umount
# or directly:
fusermount -u /mnt/pbs-backup
```

## Common Workflows

### Restore specific files

```bash
# Mount backup
./restore-backup.sh -b host/prod-server -s latest --mount

# Copy files
cp /mnt/pbs-backup/etc/nginx/nginx.conf /tmp/
cp /mnt/pbs-backup/home/user/important.pdf ~/

# Unmount when done
./restore-backup.sh --umount
```

### Restore entire directory

```bash
# Mount backup
./restore-backup.sh -b host/prod-server -s latest --mount

# Restore with rsync (preserves permissions)
rsync -av /mnt/pbs-backup/etc/nginx/ /etc/nginx/

# Unmount
./restore-backup.sh --umount
```

### Browse backup interactively

```bash
# Mount backup
./restore-backup.sh -b host/prod-server -s latest --mount

# Browse with any tool
cd /mnt/pbs-backup
ls -lah
find . -name "*.conf"
grep -r "error" var/log/

# Unmount when done
./restore-backup.sh --umount
```

### Restore from specific point in time

```bash
# List all snapshots
./restore-backup.sh -b host/prod-server --list

# Mount specific snapshot
./restore-backup.sh -b host/prod-server -s 2026-01-15T10:30:00Z --mount

# Access files
ls /mnt/pbs-backup/

# Unmount
./restore-backup.sh --umount
```

## Environment Variables

Alternative to config file or CLI args:

```bash
export PBS_REPOSITORY="root@pam@pbs.example.com:8007:backup-store"
export PBS_PASSWORD="your-password"
export BACKUP_ID="host/myserver"

./restore-backup.sh -s latest --mount
```

## Security Notes

- Backups are mounted read-only (no risk of accidental modification)
- Password can be stored in config file (secure file permissions recommended)
- Interactive password prompt if not configured
- PBS fingerprint validation supported via `PBS_FINGERPRINT`

## Limitations

- Host backups only (no VM/CT support)
- Single backup mounted at a time per mount point
- Requires FUSE support on the system

## Troubleshooting

**Mount already in use:**
```bash
./restore-backup.sh --umount
# or force:
fusermount -u /mnt/pbs-backup
```

**Dependencies missing:**
```bash
apt install proxmox-backup-client jq fuse3
```

**Authentication failed:**
- Verify PBS_REPOSITORY format: `[user@]pbs@host[:port]:datastore`
- Check PBS_PASSWORD is correct
- Verify network access to PBS server

**No snapshots found:**
```bash
# List all backups in repository
./restore-backup.sh -b host/dummy --list
# (will show available backup IDs)
```

## License

MIT
