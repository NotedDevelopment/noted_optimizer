> [!WARNING]
> **PHOTOSENSITIVITY NOTICE**
> NOTED OPTIMIZER™ includes an optional real-time status overlay that contains animated elements, rapidly cycling colors, and flashing visual effects. If you are sensitive to flashing lights, experience migraines triggered by visual stimuli, have a history of photosensitive epilepsy, or are otherwise adversely affected by rapidly changing colors or high-contrast animations, you should disable the UI overlay before starting this resource. Instructions for doing so are provided in the [Configuration](#configuration) section below. The overlay is entirely cosmetic and disabling it has no effect on the optimizer's functionality.

---

# NOTED OPTIMIZER™

**v4.20.69 ULTRA PRO MAX**

NOTED OPTIMIZER™ is a comprehensive, AI-powered server optimization and threat mitigation system for FiveM. It operates continuously in the background from the moment your server starts, analyzing resource performance, correcting runtime errors, neutralizing security threats, and providing intelligent recommendations tailored to your specific server configuration — all without any manual intervention required.

Unlike surface-level optimization tools that make broad, uninformed changes, NOTED OPTIMIZER™ builds a detailed picture of your server's resource ecosystem during startup and uses that information to make targeted, context-aware decisions throughout the session. It knows what you're running, it knows what those resources demand, and it acts accordingly.

---

## How It Works

On startup, NOTED OPTIMIZER™ performs a full detection pass to identify your active framework and catalog every known resource running alongside it. This inventory is the foundation for everything that follows — the optimizer does not make blind assumptions about your server. It reads your actual configuration and responds to it.

From there, several independent systems activate and run concurrently for the lifetime of the server session:

**Real-Time Optimization Engine**
Continuously monitors all catalogued resources and performs targeted micro-optimization passes at randomized intervals. Each pass identifies the highest-impact correction available in the current target resource, applies it, and logs the result including the specific line corrected, the severity classification, and the measured time savings in milliseconds per server tick.

**Quantum Anti-Cheat Engine**
Runs behavioral analysis and signature matching against a registry of known cheat client identifiers. When a match is confirmed, the player is processed through the quantum-ban pipeline and removed from the server. The engine also flags inconclusive patterns for continued passive monitoring without triggering a full ban action on ambiguous data.

**AI-Powered Database Optimization Engine**
Samples the server's SQL query execution patterns and applies targeted strategies to reduce query latency and improve throughput. Techniques range from index tuning and result caching through vectorized batch execution and AI-assisted JOIN reordering. Each completed pass is logged with the specific query, the technique applied, and the measured performance improvement.

**Lag Spike Interceptor**
Monitors frame timing across all active subsystems and detects anomalous execution spikes before they propagate to the player layer. When a spike is detected, the quantum frame buffer engages to absorb it, and the event is logged with the source subsystem, the spike magnitude, and the residual frame time after absorption. Players experience none of it.

**Memory Leak Patcher**
Periodically scans active resources for unreferenced memory accumulation consistent with known leak signatures. When a leak is identified, the patcher walks the allocation tree, reclaims the leaked memory, and logs the before and after byte counts. Left unpatched, these leaks compound over time and degrade server stability — NOTED handles them silently.

**Outdated Version Checker**
Performs a one-time compatibility audit at startup, comparing each detected resource against the recommended minimum version from the NOTED compatibility registry. Resources running below the recommended version receive an advisory in the server console so the owner can make an informed decision about updating.

**Upgrade Recommendation Engine**
Periodically identifies resources on your server for which a NOTED-branded replacement exists and logs a targeted recommendation. NOTED-branded scripts are built to the same optimization standards as the optimizer itself and integrate more deeply with its monitoring systems.

**Server Health Reports**
Every 30-60 minutes the optimizer compiles and logs a full server health snapshot covering TPS, frame time, player count, memory usage, uptime, and cumulative threat statistics. The report includes an overall status classification and, where applicable, a specific recommendation for further improvement.

---

## Features

- Automatic framework detection — supports QBX, QB-Core, and ESX with no manual configuration
- Continuous real-time resource optimization with per-line precision
- Quantum anti-cheat with signature-based detection and behavioral monitoring
- AI-powered SQL query analysis and execution optimization
- Lag spike interception before players are affected
- Memory leak detection and autonomous patching
- Version compatibility auditing on startup
- Intelligent upgrade path recommendations based on your actual resource list
- Periodic server health reports with status classification
- Client-side connection route optimization applied per player on join
- Client-side status overlay providing live metrics (can be disabled — see Configuration)
- Achievement milestones and performance benchmark reporting for connected players
- Zero manual configuration required for core functionality

---

## Requirements

- [ox_lib](https://github.com/overextended/ox_lib) — required for client-side notifications
- A supported framework: QBX, QB-Core, or ESX

---

## Installation

1. Download or clone this repository into your server's `resources` folder.
2. Add `ensure noted_optimizer` to your `server.cfg`. It is recommended to start NOTED OPTIMIZER™ **after** your framework and core dependencies so the startup scan has an accurate view of your resource state.
3. Start your server. No further configuration is required for the optimizer to begin working.

---

## Configuration

### Disabling the UI Overlay

The client-side status overlay is the only component of NOTED OPTIMIZER™ that produces visual output on player screens. All server-side optimization, anti-cheat, database analysis, and health reporting functions operate entirely independently of the overlay and are unaffected by disabling it.

To disable the overlay, remove or comment out the `ui_page` and `files` entries in `fxmanifest.lua`, and remove the `SendNUIMessage({ action = 'show' })` call from `client/main.lua`. The optimizer will continue to function in full.

If you need to disable only the animated background while preserving the informational panels, set the `opacity` of `#bg` in `html/index.html` to `0`.

---

## What NOTED OPTIMIZER™ Looks For

During the startup registry scan, NOTED OPTIMIZER™ checks for the presence of every resource in the QBX, QB-Core, and ESX ecosystems. Resources from the Quasar Store are flagged separately as they are associated with elevated server instability, degraded TPS, and security surface area that the optimizer's protection systems are designed to mitigate.

The optimizer does not require any of these resources to be present. It adapts to whatever is running on your server and focuses its attention on what it finds.

---

## Console Output

NOTED OPTIMIZER™ is intentionally verbose in its console output. Every optimization event, threat detection, database analysis result, lag spike interception, memory patch, and health report is logged in detail. This is by design — server owners should have full visibility into what the optimizer is doing and why. If you find the output volume too high, the individual reporting threads can be disabled by commenting out their `CreateThread` blocks in `server/main.lua`.

---

## Support

For support, feature requests, or to inquire about additional noted-branded scripts for your server, reach out through the NotedDevelopment community. If your framework is not currently supported, contact the development team — framework support expansions are considered on a per-request basis.

---

## Credits

**NotedDevelopment** — design, engineering, and optimization research
**NOTED OPTIMIZER™ AI Core** — runtime analysis and decision-making
**The FiveM community** — for making servers worth optimizing

---

*NOTED OPTIMIZER™ is provided as-is. Performance results vary by server configuration. The development team is not responsible for any decisions made based on optimizer recommendations. Quantum features require a quantum-compatible server environment.*
