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

## KRACK (Key Reinstallation Attack on WPA2)

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
  * KRACK: “WPA2 handshake, nonce reuse, key reinstallation”
  * Deauth: “802.11 management frames, DoS, handshake capture”
  * (Re)Assoc: “association flood, reassociation flood, AP resource exhaustion”
  * RogueAP: “unauthorized AP, backdoor, internal network access”
