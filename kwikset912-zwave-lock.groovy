/**
 * Copyright (C) 2026 Z Sachen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Kwikset 912 Z-Wave Lock — Hubitat Driver
 *
 * DEVICE IDENTITY
 *   The 912 SmartCode is a touchpad deadbolt.  Confirmed from Hubitat device data:
 *     Manufacturer : 144  (0x0090 — Kwikset / Spectrum Brands)
 *     Device Type  : 3    (0x0003)
 *     Device Id    : 825  (0x0339)
 *     S2 field     : 128  (0x80 = S0 legacy security key was granted)
 *   Despite carrying the Z-Wave Plus command class (0x5E), this device pairs
 *   with S0 security rather than S2.  Battery: 4 × AA alkaline.
 *
 * Z-WAVE COMMAND CLASSES (confirmed from "In Clusters" / "Secure In Clusters")
 *
 *   Non-secured (advertised openly during pairing):
 *   0x5E  ZWAVEPLUS_INFO v2     – confirms Z-Wave Plus (Gen 1)
 *   0x72  MANUFACTURER_SPECIFIC v2
 *   0x5A  DEVICE_RESET_LOCALLY v1
 *   0x98  SECURITY v1           – S0 encapsulation wrapper
 *   0x73  POWERLEVEL v1
 *   0x7A  FIRMWARE_UPDATE_MD v2
 *
 *   S0-secured (all wrapped in SecurityMessageEncapsulation before transit):
 *   0x62  DOOR_LOCK v1          – lock / unlock / operation report
 *   0x63  USER_CODE v1          – PIN management (set, delete, status)
 *   0x70  CONFIGURATION v1      – device parameters
 *   0x71  NOTIFICATION v3       – access events, jammed, tamper
 *   0x80  BATTERY v1            – battery percentage (0–100, 0xFF = critical low)
 *   0x85  ASSOCIATION v2        – Lifeline group 1
 *   0x86  VERSION v2
 *   0x59  ASSOCIATION_GROUP_INFO v1
 *   0x4C  DOOR_LOCK_LOGGING v1
 *   0x4E  SCHEDULE_ENTRY_LOCK v1
 *   0x8B  TIME_PARAMETERS v1
 *
 * NOTIFICATION EVENT MAPPING
 *   Hubitat parses 0x71 as Notification V3.  The report carries both the modern
 *   V3 fields (notificationType / event) and the legacy V1 backward-compatibility
 *   fields (v1AlarmType / v1AlarmLevel).  This driver checks V3 fields first;
 *   if they are zero it falls back to the V1 field interpretation — covering the
 *   full range of firmware variants without needing a separate handler.
 *
 *   Notification V3 — Access Control (type 6):
 *     event  1 / 2  → Manual lock / unlock
 *     event  3 / 4  → RF lock / unlock (hub-initiated)
 *     event  5 / 6  → Keypad lock / unlock  (eventParameters[0] = user ID)
 *     event  9      → Auto-lock engaged
 *     event 11      → Lock jammed
 *
 *   Notification V3 — Home Security (type 7):
 *     event  3      → Tamper: wrong code entry limit exceeded
 *     event  4      → Tamper: front cover removed
 *
 *   V1 backward-compatibility alarm types (v1AlarmType / v1AlarmLevel fields):
 *     type  9  → Deadbolt jammed
 *     type 11  → Front escutcheon tamper
 *     type 13  → Too many wrong code attempts (tamper)
 *     type 16  → All codes cleared externally
 *     type 17  → Duplicate code rejected
 *     type 18  → Keypad lock    (alarmLevel = user ID)
 *     type 19  → Keypad unlock  (alarmLevel = user ID)
 *     type 21  → RF lock (hub-initiated)
 *     type 22  → RF unlock (hub-initiated)
 *     type 24  → Manual lock (thumb-turn / inside button)
 *     type 25  → Manual unlock
 *     type 26  → Auto-lock engaged
 *     type 33  → Battery too low to operate lock
 *
 * FINGERPRINTS
 *   Confirmed from Hubitat device data (Manufacturer 144, Type 3, Id 825).
 *
 * PORTING NOTES vs. KWIKSET 914 ZIGBEE DRIVER
 *   • Battery: Z-Wave BATTERY_REPORT delivers a percentage directly — no
 *     voltage reading is available, so the chemistry-curve feature from the
 *     914 driver does not apply.  0xFF signals critically low battery.
 *   • Lock codes: Z-Wave USER_CODE_SET has no built-in response command; a
 *     USER_CODE_GET is sent a few seconds later to confirm the operation.
 *   • Events: Notification V3 Report (0x71) replaces Zigbee's Operating /
 *     Programming Event Notifications.  The user-ID field comes from
 *     eventParameters[0] (V3 format) or v1AlarmLevel (V1 fallback).
 *   • Security: Device uses S0 (0x98) despite advertising Z-Wave Plus (0x5E).
 *     zwaveSecureEncap() handles this correctly on Hubitat C8 Pro.
 *
 * CREDITS
 *   Alarm type mapping based on Kwikset Z-Wave community documentation and
 *   open-source SmartThings / Hubitat lock driver research.
 */

import groovy.json.JsonOutput
import groovy.transform.Field

@Field static final Map CMD_CLASS_VERSIONS = [
    // ── Non-secured command classes ───────────────────────────────────────────
    0x5E: 2,   // ZWAVEPLUS_INFO        (Z-Wave Plus confirmed)
    0x72: 2,   // MANUFACTURER_SPECIFIC
    0x5A: 1,   // DEVICE_RESET_LOCALLY
    0x98: 1,   // SECURITY             (S0 encapsulation wrapper)
    0x73: 1,   // POWERLEVEL
    0x7A: 2,   // FIRMWARE_UPDATE_MD
    // ── S0-secured command classes ────────────────────────────────────────────
    0x86: 2,   // VERSION
    0x80: 1,   // BATTERY
    0x62: 1,   // DOOR_LOCK
    0x63: 1,   // USER_CODE
    0x85: 2,   // ASSOCIATION
    0x59: 1,   // ASSOCIATION_GROUP_INFO
    0x71: 3,   // NOTIFICATION V3      (primary event source; V1 fields also parsed)
    0x70: 1,   // CONFIGURATION
    0x4C: 1,   // DOOR_LOCK_LOGGING
    0x4E: 1,   // SCHEDULE_ENTRY_LOCK
    0x8B: 1,   // TIME_PARAMETERS
    0x5D: 1,   // (present in device Secure In Clusters — handler not implemented)
]

metadata {
    definition(
        name:      "Kwikset 912 Z-Wave Lock",
        namespace: "community",
        author:    "Custom"
    ) {
        capability "Actuator"
        capability "Lock"
        capability "Lock Codes"
        capability "Battery"
        capability "Refresh"
        capability "Configuration"
        capability "Sensor"

        // Extra attributes — mirrors what the 914 Zigbee driver exposes
        attribute "lockJammed",   "string"   // "detected" | "clear"
        attribute "tamperAlert",  "string"   // "detected" | "clear"
        attribute "lastCodeName", "string"   // name of the user who last operated the lock

        command "clearCodes", []   // clears all PIN codes from the lock AND local state

        // ── Fingerprint ───────────────────────────────────────────────────────
        // Confirmed from Hubitat device data:
        //   Manufacturer 144 → 0x0090  |  Device Type 3 → 0x0003  |  Device Id 825 → 0x0339
        fingerprint mfr: "0090", prod: "0003", deviceId: "0339",
            deviceJoinName: "Kwikset 912 Deadbolt"
    }

    preferences {
        input name: "logEnable",
              type: "bool", title: "Enable debug logging",
              defaultValue: true

        input name: "txtEnable",
              type: "bool", title: "Enable info text logging",
              defaultValue: true

        input name: "maxCodes",
              type: "number", title: "Maximum number of PIN slots (default 30)",
              defaultValue: 30, range: "1..250"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

def installed() {
    log.info "${device.displayName}: driver installed"
    state.lockCodes      = [:]
    state.pendingCodes   = [:]
    state.pendingDeletes = [:]
    sendEvent(name: "lock",        value: "unknown")
    sendEvent(name: "lockJammed",  value: "clear")
    sendEvent(name: "tamperAlert", value: "clear")
    runIn(2, configure)
}

def updated() {
    log.info "${device.displayName}: preferences updated"
    if (logEnable) runIn(1800, logsOff)   // auto-disable debug after 30 min
    configure()
}

def logsOff() {
    log.warn "${device.displayName}: debug logging disabled after timeout"
    device.updateSetting("logEnable", [value: "false", type: "bool"])
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration & Refresh
// ─────────────────────────────────────────────────────────────────────────────

def configure() {
    if (logEnable) log.debug "${device.displayName}: configure()"
    List cmds = []

    // Associate hub with Lifeline (group 1) so unsolicited reports arrive.
    // zwaveHubNodeId is a built-in Hubitat variable.
    cmds << zwaveSecureEncap(zwave.associationV2.associationSet(
        groupingIdentifier: 1, nodeId: [zwaveHubNodeId]))
    cmds << zwaveSecureEncap(zwave.associationV2.associationGet(
        groupingIdentifier: 1))

    // Query how many user code slots the device actually supports
    cmds << zwaveSecureEncap(zwave.userCodeV1.usersNumberGet())

    // Read initial state
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationGet())
    cmds << zwaveSecureEncap(zwave.batteryV1.batteryGet())

    sendHubCommand(new hubitat.device.HubMultiAction(
        delayBetween(cmds, 500), hubitat.device.Protocol.ZWAVE))
}

def refresh() {
    if (logEnable) log.debug "${device.displayName}: refresh()"
    List cmds = []
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationGet())
    cmds << zwaveSecureEncap(zwave.batteryV1.batteryGet())
    sendHubCommand(new hubitat.device.HubMultiAction(
        delayBetween(cmds, 500), hubitat.device.Protocol.ZWAVE))
}

// ─────────────────────────────────────────────────────────────────────────────
// Commands — Lock / Unlock
// ─────────────────────────────────────────────────────────────────────────────

def lock() {
    if (logEnable) log.debug "${device.displayName}: lock()"
    sendEvent(name: "lock", value: "locking",
              descriptionText: "${device.displayName} locking")
    List cmds = []
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationSet(doorLockMode: 0xFF))
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationGet())
    sendHubCommand(new hubitat.device.HubMultiAction(
        delayBetween(cmds, 3000), hubitat.device.Protocol.ZWAVE))
}

def unlock() {
    if (logEnable) log.debug "${device.displayName}: unlock()"
    sendEvent(name: "lock", value: "unlocking",
              descriptionText: "${device.displayName} unlocking")
    List cmds = []
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationSet(doorLockMode: 0x00))
    cmds << zwaveSecureEncap(zwave.doorLockV1.doorLockOperationGet())
    sendHubCommand(new hubitat.device.HubMultiAction(
        delayBetween(cmds, 3000), hubitat.device.Protocol.ZWAVE))
}

// ─────────────────────────────────────────────────────────────────────────────
// Commands — Lock Codes capability
// ─────────────────────────────────────────────────────────────────────────────

def setCode(codeNumber, code, name = null) {
    if (logEnable) log.debug "${device.displayName}: setCode(${codeNumber}, [PIN], ${name})"

    codeNumber = codeNumber as int
    if (codeNumber < 1 || codeNumber > (maxCodes ?: 30)) {
        log.warn "${device.displayName}: code slot ${codeNumber} out of range (1..${maxCodes ?: 30})"
        return
    }
    if (!code || !(code ==~ /^\d{4,8}$/)) {
        log.warn "${device.displayName}: PIN must be 4–8 numeric digits"
        return
    }

    def codeName = name ?: "Code ${codeNumber}"
    if (!state.pendingCodes) state.pendingCodes = [:]
    state.pendingCodes["${codeNumber}"] = [name: codeName]

    // Z-Wave USER_CODE spec: each byte is the ASCII value of the digit (0x30–0x39).
    def userCode = code.bytes.collect { it & 0xFF }
    sendHubCommand(new hubitat.device.HubAction(
        zwaveSecureEncap(zwave.userCodeV1.userCodeSet(
            userId: codeNumber, userIdStatus: 1, userCode: userCode)),
        hubitat.device.Protocol.ZWAVE))

    // USER_CODE_SET has no built-in response; verify by reading the slot back.
    runIn(4, "checkCodeSlot", [data: [slot: codeNumber], overwrite: false])
}

def deleteCode(codeNumber) {
    if (logEnable) log.debug "${device.displayName}: deleteCode(${codeNumber})"
    codeNumber = codeNumber as int
    if (!state.pendingDeletes) state.pendingDeletes = [:]
    state.pendingDeletes["${codeNumber}"] = true

    // userIdStatus=0 marks the slot as Available (erased)
    sendHubCommand(new hubitat.device.HubAction(
        zwaveSecureEncap(zwave.userCodeV1.userCodeSet(
            userId: codeNumber, userIdStatus: 0, userCode: [])),
        hubitat.device.Protocol.ZWAVE))

    runIn(4, "checkCodeSlot", [data: [slot: codeNumber], overwrite: false])
}

def getCodes() {
    if (logEnable) log.debug "${device.displayName}: getCodes()"
    updateLockCodesAttribute(state.lockCodes ?: [:])
    return []
}

def setCodeLength(length) {
    if (logEnable) log.debug "${device.displayName}: setCodeLength(${length})"
    sendEvent(name: "codeLength", value: length as int,
              descriptionText: "${device.displayName} code length set to ${length}")
}

def clearCodes() {
    log.info "${device.displayName}: clearCodes() — clearing ALL codes"
    def codes = state.lockCodes ?: [:]
    state.lockCodes    = [:]
    state.pendingCodes = [:]
    state.pendingDeletes = [:]
    updateLockCodesAttribute([:])
    sendEvent(name: "codeChanged", value: "all deleted",
              descriptionText: "${device.displayName} all codes cleared")

    def slots = codes.keySet().collect { it as int }.sort()
    if (!slots) {
        if (logEnable) log.debug "${device.displayName}: no tracked codes to delete from lock"
        return
    }

    List cmds = []
    slots.each { slot ->
        cmds << zwaveSecureEncap(zwave.userCodeV1.userCodeSet(
            userId: slot, userIdStatus: 0, userCode: []))
    }
    sendHubCommand(new hubitat.device.HubMultiAction(
        delayBetween(cmds, 500), hubitat.device.Protocol.ZWAVE))
}

// ── Code verification (scheduled via runIn after set / delete) ────────────────

/**
 * Sends USER_CODE_GET for the given slot; the response (UserCodeReport) is
 * handled below and drives the codeChanged event and lockCodes state update.
 * Called by runIn — must not be private.
 */
void checkCodeSlot(Map data) {
    if (logEnable) log.debug "${device.displayName}: checkCodeSlot — reading slot ${data.slot}"
    sendHubCommand(new hubitat.device.HubAction(
        zwaveSecureEncap(zwave.userCodeV1.userCodeGet(userId: data.slot as int)),
        hubitat.device.Protocol.ZWAVE))
}

// ─────────────────────────────────────────────────────────────────────────────
// Z-Wave Parse — entry point
// ─────────────────────────────────────────────────────────────────────────────

def parse(String description) {
    if (logEnable) log.debug "${device.displayName}: parse → ${description}"
    hubitat.zwave.Command cmd = zwave.parse(description, CMD_CLASS_VERSIONS)
    if (cmd) {
        zwaveEvent(cmd)
    } else {
        log.warn "${device.displayName}: could not parse: ${description}"
    }
    return null
}

// ─────────────────────────────────────────────────────────────────────────────
// Z-Wave event handlers
// ─────────────────────────────────────────────────────────────────────────────

// S0 security encapsulation — unwrap and re-dispatch
void zwaveEvent(hubitat.zwave.commands.securityv1.SecurityMessageEncapsulation cmd) {
    hubitat.zwave.Command inner = cmd.encapsulatedCommand(CMD_CLASS_VERSIONS)
    if (inner) {
        zwaveEvent(inner)
    } else {
        log.warn "${device.displayName}: could not extract secure command: ${cmd}"
    }
}

// Door Lock Operation Report — lock/unlock state confirmed by device
void zwaveEvent(hubitat.zwave.commands.doorlockv1.DoorLockOperationReport cmd) {
    if (logEnable) log.debug "${device.displayName}: DoorLockOperationReport: ${cmd}"
    def lockVal = cmd.doorLockMode == 0xFF ? "locked" :
                  cmd.doorLockMode == 0x00 ? "unlocked" : "unknown"
    if (txtEnable) log.info "${device.displayName}: is ${lockVal}"
    sendEvent(name: "lock", value: lockVal,
              descriptionText: "${device.displayName} is ${lockVal}")
    if (lockVal != "unknown") {
        sendEvent(name: "lockJammed", value: "clear")
    }
}

// Battery Report — 0x00–0x64 = 0–100%, 0xFF = critically low
void zwaveEvent(hubitat.zwave.commands.batteryv1.BatteryReport cmd) {
    if (logEnable) log.debug "${device.displayName}: BatteryReport: ${cmd}"
    if (cmd.batteryLevel == 0xFF) {
        log.warn "${device.displayName}: LOW BATTERY — replace batteries soon"
        sendEvent(name: "battery", value: 1, unit: "%",
                  descriptionText: "${device.displayName} battery critically low")
    } else {
        def pct = cmd.batteryLevel as int
        if (txtEnable) log.info "${device.displayName}: battery is ${pct} %"
        sendEvent(name: "battery", value: pct, unit: "%",
                  descriptionText: "${device.displayName} battery: ${pct} %")
    }
}

/**
 * Notification V3 Report — the primary event source for this device.
 *
 * Hubitat parses class 0x71 as notificationv3 (per CMD_CLASS_VERSIONS).
 * The report carries both V3 fields (notificationType / event) and V1
 * backward-compatibility fields (v1AlarmType / v1AlarmLevel).  We check
 * the V3 fields first; if they are zero we fall back to the V1 interpretation.
 * This covers the full range of firmware variants in a single handler.
 */
void zwaveEvent(hubitat.zwave.commands.notificationv3.NotificationReport cmd) {
    if (logEnable) log.debug "${device.displayName}: NotificationReport: ${cmd}"
    if (cmd.notificationType && cmd.notificationType != 0) {
        parseNotificationEvent(cmd.notificationType as int,
                               cmd.event as int,
                               cmd.eventParameters ?: [])
    } else if (cmd.v1AlarmType && cmd.v1AlarmType != 0) {
        parseAlarmV1Event(cmd.v1AlarmType as int, cmd.v1AlarmLevel as int)
    } else {
        if (logEnable) log.debug "${device.displayName}: empty / unrecognised notification report"
    }
}

/**
 * User Code Report — arrives after USER_CODE_GET (sent by checkCodeSlot).
 *
 * userIdStatus == 1 → slot is occupied (set succeeded or code exists)
 * userIdStatus == 0 → slot is available (delete succeeded or never set)
 *
 * Note: for security, many locks zero out the actual PIN bytes in the report.
 * The status field is reliable even when the PIN bytes are redacted.
 */
void zwaveEvent(hubitat.zwave.commands.usercodev1.UserCodeReport cmd) {
    if (logEnable) log.debug "${device.displayName}: UserCodeReport userId=${cmd.userId} status=${cmd.userIdStatus}"
    def slot    = "${cmd.userId}"
    def pending = state.pendingCodes   ?: [:]
    def pendDel = state.pendingDeletes ?: [:]
    def codes   = state.lockCodes      ?: [:]

    if (cmd.userIdStatus == 1) {
        // Slot occupied — confirm a pending set or record a newly discovered code
        if (pending[slot]) {
            def info = pending.remove(slot)
            state.pendingCodes = pending
            codes[slot] = [name: info.name]
            state.lockCodes = codes
            updateLockCodesAttribute(codes)
            if (txtEnable) log.info "${device.displayName}: code slot ${slot} (${info.name}) confirmed set"
            sendEvent(name: "codeChanged", value: "${slot} set",
                      descriptionText: "${device.displayName} code slot ${slot} set")
        } else if (!codes[slot]) {
            // Code exists on lock but not tracked locally — add placeholder
            codes[slot] = [name: "Code ${cmd.userId}"]
            state.lockCodes = codes
            updateLockCodesAttribute(codes)
            sendEvent(name: "codeChanged", value: "${slot} set",
                      descriptionText: "${device.displayName} code slot ${slot} discovered")
        }
    } else {
        // Slot available — confirm a pending delete, or surface a set failure
        pendDel.remove(slot)
        state.pendingDeletes = pendDel

        if (codes.containsKey(slot)) {
            codes.remove(slot)
            state.lockCodes = codes
            updateLockCodesAttribute(codes)
            if (txtEnable) log.info "${device.displayName}: code slot ${slot} confirmed deleted"
            sendEvent(name: "codeChanged", value: "${slot} deleted",
                      descriptionText: "${device.displayName} code slot ${slot} deleted")
        }
        if (pending[slot]) {
            def info = pending.remove(slot)
            state.pendingCodes = pending
            log.warn "${device.displayName}: code slot ${slot} (${info?.name}) set FAILED — slot is still empty"
            sendEvent(name: "codeChanged", value: "${slot} failed",
                      descriptionText: "${device.displayName} code slot ${slot} set failed")
        }
    }
}

// Users Number Report — device tells us its maximum slot count
void zwaveEvent(hubitat.zwave.commands.usercodev1.UsersNumberReport cmd) {
    if (logEnable) log.debug "${device.displayName}: UsersNumberReport: supportedUsers=${cmd.supportedUsers}"
    state.maxSupportedCodes = cmd.supportedUsers
    if (txtEnable) log.info "${device.displayName}: device supports ${cmd.supportedUsers} user code slots"
}

// Association Report — informational
void zwaveEvent(hubitat.zwave.commands.associationv2.AssociationReport cmd) {
    if (logEnable) log.debug "${device.displayName}: AssociationReport group ${cmd.groupingIdentifier}: ${cmd.nodeId}"
}

// Manufacturer Specific Report — informational
void zwaveEvent(hubitat.zwave.commands.manufacturerspecificv2.ManufacturerSpecificReport cmd) {
    if (logEnable) log.debug "${device.displayName}: ManufacturerSpecificReport: " +
        "mfr=0x${String.format('%04X', cmd.manufacturerId)} " +
        "prod=0x${String.format('%04X', cmd.productTypeId)} " +
        "id=0x${String.format('%04X', cmd.productId)}"
}

// Version Report — informational
void zwaveEvent(hubitat.zwave.commands.versionv1.VersionReport cmd) {
    if (logEnable) log.debug "${device.displayName}: VersionReport: ${cmd}"
}

// Catch-all for unhandled commands
void zwaveEvent(hubitat.zwave.Command cmd) {
    if (logEnable) log.debug "${device.displayName}: unhandled Z-Wave command: ${cmd}"
}

// ─────────────────────────────────────────────────────────────────────────────
// Alarm / Notification parsers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Kwikset 912 Alarm V1 event table.
 *
 * alarmLevel carries supplementary data — for keypad events it is the user ID
 * of the slot whose PIN was entered.  For other event types it is typically 0.
 *
 * Values are based on Kwikset Z-Wave community documentation; verify against
 * live device logs (debug mode) if any events appear as "unhandled".
 */
private void parseAlarmV1Event(int alarmType, int alarmLevel) {
    if (logEnable) log.debug "${device.displayName}: Alarm V1 type=${alarmType} level=${alarmLevel}"
    switch (alarmType) {
        case 9:   // Deadbolt jammed
            log.warn "${device.displayName}: deadbolt jammed"
            sendEvent(name: "lockJammed", value: "detected",
                      descriptionText: "${device.displayName}: deadbolt jammed")
            sendEvent(name: "lock",       value: "unknown",
                      descriptionText: "${device.displayName}: lock state unknown (jammed)")
            break

        case 18:  // Keypad lock — alarmLevel = user ID
            handleKeypadEvent("locked", "locked via keypad", alarmLevel)
            break

        case 19:  // Keypad unlock — alarmLevel = user ID
            handleKeypadEvent("unlocked", "unlocked via keypad", alarmLevel)
            break

        case 21:  // RF lock (hub / Z-Wave controller)
            handleSimpleLockEvent("locked", "locked via RF")
            break

        case 22:  // RF unlock
            handleSimpleLockEvent("unlocked", "unlocked via RF")
            break

        case 24:  // Manual lock (thumb-turn or inside push-button)
            handleSimpleLockEvent("locked", "locked manually")
            break

        case 25:  // Manual unlock
            handleSimpleLockEvent("unlocked", "unlocked manually")
            break

        case 26:  // Auto-lock engaged
            handleSimpleLockEvent("locked", "auto-locked")
            break

        case 11:  // Front escutcheon tamper
        case 13:  // Too many wrong code attempts
            log.warn "${device.displayName}: tamper alert — alarm type ${alarmType}"
            sendEvent(name: "tamperAlert", value: "detected",
                      descriptionText: "${device.displayName}: tamper detected (alarm type ${alarmType})")
            break

        case 16:  // All user codes cleared externally (on the lock itself)
            state.lockCodes = [:]
            updateLockCodesAttribute([:])
            sendEvent(name: "codeChanged", value: "all deleted",
                      descriptionText: "${device.displayName}: all codes cleared on lock")
            if (txtEnable) log.info "${device.displayName}: all codes cleared externally"
            break

        case 17:  // Duplicate code rejected by lock
            log.warn "${device.displayName}: code set rejected — duplicate code"
            sendEvent(name: "codeChanged", value: "duplicate",
                      descriptionText: "${device.displayName}: duplicate code rejected")
            break

        case 33:  // Battery too low to operate lock
            log.warn "${device.displayName}: BATTERY TOO LOW — replace batteries immediately"
            sendEvent(name: "battery", value: 0, unit: "%",
                      descriptionText: "${device.displayName}: battery too low to operate")
            break

        default:
            if (logEnable) log.debug "${device.displayName}: unhandled alarm type ${alarmType} level ${alarmLevel}"
    }
}

/**
 * Z-Wave Notification V3 handler — for devices or firmware that send the newer
 * format.  Type 6 = Access Control.  Type 7 = Home Security.
 */
private void parseNotificationEvent(int notifType, int notifEvent, List params) {
    if (logEnable) log.debug "${device.displayName}: Notification V3 type=${notifType} event=${notifEvent} params=${params}"

    if (notifType == 6) {   // Access Control
        def userID = (params && params.size() > 0) ? (params[0] as int) : 0
        switch (notifEvent) {
            case 1:   // Manual lock
                handleSimpleLockEvent("locked", "locked manually")
                break
            case 2:   // Manual unlock
                handleSimpleLockEvent("unlocked", "unlocked manually")
                break
            case 3:   // RF lock
                handleSimpleLockEvent("locked", "locked via RF")
                break
            case 4:   // RF unlock
                handleSimpleLockEvent("unlocked", "unlocked via RF")
                break
            case 5:   // Keypad lock — eventParameter[0] = user ID
                handleKeypadEvent("locked", "locked via keypad", userID)
                break
            case 6:   // Keypad unlock — eventParameter[0] = user ID
                handleKeypadEvent("unlocked", "unlocked via keypad", userID)
                break
            case 9:   // Auto-lock
                handleSimpleLockEvent("locked", "auto-locked")
                break
            case 11:  // Lock jammed
                log.warn "${device.displayName}: deadbolt jammed"
                sendEvent(name: "lockJammed", value: "detected",
                          descriptionText: "${device.displayName}: deadbolt jammed")
                sendEvent(name: "lock", value: "unknown",
                          descriptionText: "${device.displayName}: lock state unknown (jammed)")
                break
            default:
                if (logEnable) log.debug "${device.displayName}: unhandled access control event ${notifEvent}"
        }
    } else if (notifType == 7) {   // Home Security
        switch (notifEvent) {
            case 3:   // Tamper: wrong code limit exceeded
            case 4:   // Tamper: cover removed
                log.warn "${device.displayName}: tamper alert — notification event ${notifEvent}"
                sendEvent(name: "tamperAlert", value: "detected",
                          descriptionText: "${device.displayName}: tamper detected")
                break
            default:
                if (logEnable) log.debug "${device.displayName}: unhandled home security event ${notifEvent}"
        }
    } else {
        if (logEnable) log.debug "${device.displayName}: unhandled notification type ${notifType}"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared lock-event helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fires lock + lockJammed events for a keypad operation.
 * Looks up the code name from state and sets lastCodeName + usedCode data so
 * that Lock Code Manager can attribute the event to the named user — mirrors
 * the same pattern used in the 914 Zigbee driver.
 */
private void handleKeypadEvent(String lockVal, String action, int userID) {
    def codeName = getCodeName(userID)
    def desc = "${device.displayName} ${action}" + (codeName ? " (${codeName})" : "")
    if (txtEnable) log.info desc
    if (codeName) sendEvent(name: "lastCodeName", value: codeName)
    def evtData = userID > 0 ? [usedCode: userID, codeName: codeName ?: ""] : [:]
    sendEvent(name: "lock",       value: lockVal, descriptionText: desc, data: evtData)
    sendEvent(name: "lockJammed", value: "clear")
}

/** Fires lock + lockJammed events for a non-keypad operation (RF, manual, auto). */
private void handleSimpleLockEvent(String lockVal, String action) {
    def desc = "${device.displayName} ${action}"
    if (txtEnable) log.info desc
    sendEvent(name: "lock",       value: lockVal, descriptionText: desc)
    sendEvent(name: "lockJammed", value: "clear")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

private void updateLockCodesAttribute(Map codes) {
    sendEvent(name: "lockCodes", value: JsonOutput.toJson(codes),
              descriptionText: "${device.displayName} lock codes updated")
}

private String getCodeName(int userID) {
    if (userID == 0) return null
    return (state.lockCodes ?: [:])["${userID}"]?.name
}
