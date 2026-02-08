# Cisco CDP Crawler - Docker Version

Standalone Docker image for discovering Cisco devices via CDP protocol.

## Status
✓ **Ready for Testing** - Tested in Eve-NG lab environment

## Quick Start

```bash
docker-compose up
# Enter credentials at prompts
# Output: devices.csv
```

## What It Does
- Discovers devices via Cisco Discovery Protocol (CDP)
- Extracts: hostname, model, serial number, firmware version
- Handles deduplication on redundant L2 links
- Exports results to CSV

## Requirements
- Cisco devices with CDP enabled
- SSH access (admin credentials)
- Network connectivity to devices

## Output
CSV with columns: hostname, model, serial, firmware, device_type, status

## Notes
- Lab tested on Eve-NG (vIOS devices)
- Production testing in progress on WAN routers
- **Status:** Ready for Testing (2026-02-08)
