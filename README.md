# Kwikset 912 Z-Wave Plus Lock — Hubitat Driver

A Hubitat Elevation driver for the **Kwikset 912 SmartCode Z-Wave Plus deadbolt** with full Lock Code Manager integration, tamper/jam detection, and device-specific Z-Wave parsing.

---

## Why this driver instead of the Generic Z-Wave Lock

The Generic Z-Wave Lock driver that ships with Hubitat is generally competent and will get the basics working. This driver goes further in four specific areas:

### 1. Device-specific command class versions

Every Z-Wave device advertises which command class versions it supports. Hubitat's `zwave.parse()` uses the version map you provide to select the right parser for each incoming frame — if the version is wrong, fields can come back empty or misread.

The Generic driver uses conservative fallback versions that work across many devices. This driver uses the exact versions confirmed from this device's own pairing data:

| Class | Hex | Version used |
|---|---|---|
| NOTIFICATION | 0x71 | 3 |
| VERSION | 0x86 | 2 |
| ASSOCIATION | 0x85 | 2 |
| MANUFACTURER_SPECIFIC | 0x72 | 2 |

### 2. `lockJammed` and `tamperAlert` attributes

The Generic driver does not expose these as named attributes. This driver adds:

- **`lockJammed`** — set to `"detected"` when the deadbolt reports a jam; cleared automatically on the next successful lock or unlock. Use this in Rule Machine to trigger an alert or retry.
- **`tamperAlert`** — set to `"detected"` on wrong-code limit exceeded or front cover removed events.

### 3. `lastCodeName` attribute

After any keypad lock or unlock, this attribute is updated with the name of the user whose PIN was used. Useful for dashboards or simple notification rules without needing Lock Code Manager involved.

### 4. Lock Code Manager user attribution

When a keypad event fires the `lock` event, this driver includes `[usedCode: slotNumber, codeName: "Name"]` in the event's `data` map. This is what allows Lock Code Manager to log and act on **who** locked or unlocked the door, not just that it happened. The Generic driver typically fires the lock event without this data, so LCM sees the event but cannot attribute it to a named user.

### What is the same

- **Battery percentage** — Z-Wave `BATTERY_REPORT` delivers a pre-computed percentage from the lock's own firmware. Both drivers pass it through unchanged. Note: Kwikset's battery curve is optimistic — expect `100%` longer than warranted, followed by a steeper drop near the end.
- **Core lock / unlock** — identical behaviour.
- **Basic code set / delete** — both drivers implement the `Lock Codes` capability.

---

## Confirmed device identity

Verified from Hubitat's Device Data page after pairing:

| Field | Value | Hex |
|---|---|---|
| Manufacturer | 144 | 0x0090 (Kwikset / Spectrum Brands) |
| Device Type | 3 | 0x0003 |
| Device Id | 825 | 0x0339 |
| Protocol | Z-Wave Plus | `0x5E` present in In Clusters |
| Security | S2: 128 | 0x80 = S0 legacy security |

The device is Z-Wave Plus (confirmed by `0x5E` ZWAVEPLUS_INFO in its cluster list) but pairs using S0 legacy security rather than S2 — common for Z-Wave Plus Gen 1 hardware that predates mandatory S2.

**Non-secured command classes:** `0x5E, 0x72, 0x5A, 0x98, 0x73, 0x7A`

**S0-secured command classes:** `0x86, 0x80, 0x62, 0x63, 0x85, 0x59, 0x71, 0x70, 0x4E, 0x8B, 0x4C, 0x5D`

---

## Features

| Feature | Details |
|---|---|
| Lock / Unlock | With `"locking"` / `"unlocking"` transitional states |
| Battery % | Passed through from device firmware (Z-Wave `BATTERY_REPORT`) |
| PIN code management | Full `Lock Codes` capability — set, delete, clear all |
| Code verification | `USER_CODE_GET` confirms each set or delete before firing `codeChanged` |
| LCM user attribution | `usedCode` + `codeName` included in keypad lock/unlock events |
| Last user | `lastCodeName` attribute updated on every keypad operation |
| Lock jammed | `lockJammed` attribute via Notification event 11 / V1 alarm type 9 |
| Tamper alerts | `tamperAlert` attribute — wrong-code limit, cover removed |
| Notification format | Handles both V3 Notification and V1 backward-compatibility alarm fields |
| Debug logging | Auto-disables after 30 minutes |

---

## Installation

### Option A — Import by URL (easiest)

1. In Hubitat, go to **Drivers Code → + New Driver → Import**
2. Paste this URL:
   ```
   https://raw.githubusercontent.com/iamnof1/hubitat-kwikset-912-zwave/master/kwikset912-zwave-lock.groovy
   ```
3. Click **Import**, then **Save**

### Option B — Manual

1. Open `kwikset912-zwave-lock.groovy` from this repo
2. Copy the entire contents
3. In Hubitat, go to **Drivers Code → + New Driver**
4. Paste and click **Save**

### Assign the driver to your lock

1. In Hubitat, go to **Devices** and open your Kwikset 912
2. Change **Type** to `Kwikset 912 Z-Wave Lock`
3. Click **Save Device**
4. Click **Configure** to push association settings to the lock and read initial state

---

## Preferences

| Setting | Default | Description |
|---|---|---|
| Debug logging | On | Auto-disables after 30 minutes |
| Info text logging | On | Logs lock/unlock events and battery to the hub log |
| Max PIN slots | 30 | Upper bound for code slot numbers accepted by `setCode` |

---

## Changelog

### 2026-02-21

- Initial release

---

## License

GPL-3.0 — see [LICENSE](LICENSE)

This driver is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3.

© 2026 Z Sachen
