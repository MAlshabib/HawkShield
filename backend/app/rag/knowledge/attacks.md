# Most Common Wireless Network Attacks

---

## SSDP (Simple Service Discovery Protocol) – Reflection/Amplification

### Definition
SSDP is a UDP-based discovery protocol (UPnP, port 1900) on many IoT/consumer devices. Attackers spoof a victim’s IP to trigger large reply bursts from misconfigured devices—an amplification DDoS.

### Real-time harm
* Saturates the wireless backhaul and AP CPU, causing throughput collapse and high latency.
* Starves legitimate clients (video calls, IoT sensors) and triggers timeouts/packet loss.
* Can crash weak home/SMB routers or force AP reboots under load.

### Defenses
* Disable or restrict UPnP/SSDP on gateways and IoT devices when not needed.
* Filter/ACL UDP/1900 at the perimeter; rate-limit SSDP responses.
* Use DDoS protection (upstream scrubbing, reflection-source blacklists).
* Keep router/AP firmware updated; segment IoT on separate VLAN/SSID.

---

## Evil_Twin (Evil Twin AP / SSID Impersonation)

### Definition
A malicious access point that mimics a legitimate SSID (same name/security settings) to trick clients into connecting; often combined with captive-portal phishing or SSL-stripping.

### Real-time harm
* Man-in-the-Middle (MitM): intercepts traffic, steals credentials/tokens, injects malware.
* Session hijacking and downgrade of encryption for unsuspecting clients.
* Works even better when attackers send deauth frames to kick clients off the real AP and force them to join the twin.

### Defenses
* Prefer WPA3-Enterprise (or WPA2-Enterprise with certificate validation).
* Enforce server certificate pinning on supplicants; user training to verify SSID.
* Deploy WIPS/WIDS to detect SSID spoofing and rogue beacons.
* Use VPN on untrusted Wi‑Fi; disable auto-join to open/unknown SSIDs.

---

## Krack (Key Reinstallation Attack on WPA2)

### Definition
A vulnerability in the WPA2 4-way handshake where attackers force nonce/key reinstallation, enabling replay and, in some cases, decryption/injection of frames. Impact depends on client patch status and cipher (e.g., TKIP/CCMP).

### Real-time harm
* Decrypts or manipulates traffic from vulnerable clients on the fly.
* Enables credential theft and data exfiltration on unpatched IoT/legacy devices.
* Bypasses expected confidentiality even on “secure” WPA2 networks until endpoints are patched; WPA3 is designed to resist this class.

### Defenses
* Patch clients/APs with KRACK fixes; prefer WPA3 (SAE) where possible.
* Disable legacy ciphers (TKIP); enforce strong CCMP/GCMP.
* Use end-to-end encryption (HTTPS, TLS, SSH, VPN) to limit plaintext exposure.
* Monitor for anomalous replay/injection patterns in wireless IDS.

---

## Kr00k (CVE-2019-15126 – All-Zero Temporal Key Disclosure)

### Definition
A vulnerability in Broadcom and Cypress FullMAC Wi-Fi chips (found in a very large
population of phones, tablets, laptops, IoT devices and consumer APs). When a station
is disassociated, the chip clears the session temporal key (TK) in its hardware key
slot to **all zeros**, but it still transmits whatever frames were already sitting in
its transmit buffer — now encrypted under that all-zero TK. Those few kilobytes are
therefore decryptable by anyone within radio range with no key material at all. The
attack does not break WPA2 itself: it exploits a flawed key-teardown implementation
below the protocol. An attacker forces disassociation repeatedly (spoofed disassoc
frames are enough, see `Disas`) and milks the buffer a few frames at a time.
Affects CCMP under both WPA2-Personal and WPA2-Enterprise.

### Real-time harm
* Leaks the tail of the encrypted session — the frames most likely to carry request
  headers, cookies, tokens or DNS lookups — in cleartext-equivalent form.
* Scales by repetition: each forced disassociation yields another buffer flush, so a
  patient attacker accumulates plaintext from a "secure" WPA2 link indefinitely.
* Silent to the victim: the client simply re-associates, so the user sees at most a
  brief hiccup and nothing in the logs says data was disclosed.
* Firmware-level, so it survives OS hardening and is invisible to host-based tooling.

### Defenses
* Patch firmware/drivers on every Broadcom/Cypress device (vendor fixes shipped from
  2019 onward); this is the only real fix, since the flaw is in the chip's key handling.
* Enable 802.11w/PMF so an attacker cannot cheaply force the disassociations the
  attack depends on.
* Use end-to-end encryption (HTTPS/TLS, VPN) so a decrypted buffer yields ciphertext.
* Prefer WPA3/GCMP hardware on new purchases; retire unpatchable IoT devices.
* Watch for the signature HawkShield keys on: repeated disassociation events for one
  station immediately followed by a short burst of data frames.

---

## Deauth (802.11 Deauthentication/Disassociation)

### Definition
Abuse of management frames (historically unauthenticated) to send forged deauth/disassoc messages that force clients off an AP.

### Real-time harm
* Denial of Service: clients continuously drop/reconnect; apps freeze; VoIP/video collapse.
* Used to coerce roaming to a malicious AP (Evil Twin) or to capture handshakes for offline attacks.
* Causes spikes in power drain on mobile/IoT due to repeated re-associations.

### Defenses
* Enable 802.11w/PMF (Protected Management Frames) on APs/clients.
* Use WIPS/WIDS to detect deauth floods and auto-contain sources.
* Reduce open SSIDs; enforce strong auth; tune roaming thresholds to resist kicks.
* Segment critical devices; prioritize voice/video QoS to mitigate disruption.

---

## Disas (802.11 Disassociation Flood)

### Definition
A flood of forged **disassociation** frames — 802.11 management subtype **10 (0x0A)**,
which is *not* the same frame as a deauthentication (subtype **12 / 0x0C**). The
distinction matters operationally: deauthentication tears down the 802.11
authentication as well as the association, so the client must re-authenticate before
re-associating; disassociation ends only the association and leaves the station
authenticated, so it can re-associate immediately. That makes a disassociation flood
cheaper to sustain and faster-cycling — the victim churns through
disassociate/re-associate rounds rather than dropping cleanly off the BSS.
Frames are spoofed with the AP's address so they appear to come from the BSS, and
carry a plausible reason code (1 "unspecified", 4 "inactivity", 8 "leaving BSS").
Like all pre-802.11w management frames they are unauthenticated, so no key material
is needed to forge them.

### Real-time harm
* Denial of Service by churn: clients stay nominally connected but lose their
  association repeatedly, so TCP sessions stall, VoIP/video break up and roaming
  decisions thrash.
* Management-frame storms consume airtime and AP/controller association state,
  degrading clients that are not themselves targeted.
* Used as the trigger stage for other attacks — it is the cheap way to force the
  buffer flush that `Kr00k` exploits, and to push a client toward an `Evil_Twin`.
* Harder to spot than a deauth flood in casual monitoring, because clients never
  fully disconnect and the dashboard's "clients associated" count barely moves.

### Defenses
* Enable 802.11w/PMF (Protected Management Frames) — it authenticates disassociation
  and deauthentication alike and is the direct fix.
* Rate-limit and alert on disassociation frames per BSSID/station in WIPS/WIDS;
  count subtype 10 separately from subtype 12 so the two floods stay distinguishable.
* Contain the source: correlate the spoofed address with RF signal strength to find
  the real transmitter rather than the forged MAC.
* Keep AP/controller firmware current and enable vendor management-frame DoS
  protection; segment critical devices onto PMF-required SSIDs.

---

## (Re)Assoc – Association/Reassociation Floods

### Definition
Flooding an AP with large volumes of association or reassociation requests, often from spoofed MACs, to exhaust memory/CPU on the AP or controller.

### Real-time harm
* Resource exhaustion on the AP → legitimate clients can’t join or are dropped.
* Severe airtime contention and management-frame storms that degrade all traffic.
* Can trigger protection mechanisms (rate limiting) that further throttle normal users.

### Defenses
* Rate-limit association requests; enable station/MAC throttling on controllers.
* Use WIPS to identify spoofed MAC behavior and contain offending stations.
* Capacity-plan RF/channelization; isolate public/guest SSIDs on separate radios.
* Keep AP/controller firmware updated; enable DoS protection features.

---

## RogueAP (Unauthorized Access Point on the Inside)

### Definition
An unauthorized AP connected inside the organization’s wired network (malicious or accidental). It creates a backdoor that bypasses official WLAN security controls.

### Real-time harm
* Provides attackers direct LAN access via Wi‑Fi → lateral movement, malware staging.
* Enables MitM and credential harvesting for any client that associates.
* Interferes with RF environment (channel overlap), causing performance degradation and unstable roaming.

### Defenses
* Continuous rogue AP scanning (WIPS); auto-containment policies.
* Port security/802.1X on switches; NAC to block unknown APs/hosts.
* Network segmentation and least privilege; monitor for anomalous DHCP/DNS.
* Physical security and asset management to prevent shadow IT.

---

### Notes for your RAG indexing

* Keep these as standalone sections; use the `##` headings as chunk titles.
* Subsections are marked with `###` (Definition / Real-time harm / Defenses).
* Useful keywords:
  * SSDP: “UPnP, UDP/1900, reflection, amplification, IoT”
  * Evil_Twin: “SSID spoofing, MitM, captive portal, SSL strip”
  * Krack: “WPA2 handshake, nonce reuse, key reinstallation”
  * Kr00k: “CVE-2019-15126, all-zero TK, Broadcom, Cypress, buffer disclosure”
  * Deauth: “802.11 management frames, subtype 12, DoS, handshake capture”
  * Disas: “disassociation flood, subtype 10, reason code, association churn”
  * (Re)Assoc: “association flood, reassociation flood, AP resource exhaustion”
  * RogueAP: “unauthorized AP, backdoor, internal network access”

* The `##` heading of each section is the **exact** `predicted_label` value the
  detector writes to the database (`feature_spec.ATTACK_CLASSES`), followed by a
  human-readable gloss in parentheses or after a dash. Keep it that way: the agent
  looks sections up by that label, so renaming a heading silently unhooks a class.
