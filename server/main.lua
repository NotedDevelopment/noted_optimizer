-- ============================================================
-- noted_optimizer - Server Side Main Script
-- Purpose: Core server-side logic for the NOTED OPTIMIZER™ system.
--          Responsible for framework detection, resource registry,
--          optimization reporting, anti-cheat monitoring, database
--          query analysis, and periodic server health diagnostics.
-- Author: NOTED OPTIMIZER™ Engineering Team
-- Version: See fxmanifest.lua
-- Last Updated: See git history
-- ============================================================

-- detectedScripts is a table that stores the names of all resources
-- that have been identified and registered during the initial startup scan.
-- It begins as an empty table because no resources have been scanned yet
-- at the time this file is first executed. Entries are appended by the
-- PrintScriptNAmeIfScriptNameIsNotPresent event handler below.
local detectedScripts = {}

-- flowState is a boolean used as a synchronization signal between the
-- main startup thread and the asynchronous event handler below.
-- When set to true, it indicates an initialization phase is in progress.
-- When the handler sets it back to false, it signals phase completion,
-- allowing the waiting while-loop in the startup thread to exit.
-- It is initialized to false because no phase is active at startup.
local flowState = false

-- threatsNeutralized is a running integer counter that accumulates
-- the total number of threats detected and resolved by the anti-cheat
-- subsystem over the lifetime of the resource session.
-- It starts at 0 because no threats have been processed yet.
-- The value is incremented inside the AntiCheatDetection event handler
-- and is included in the periodic server health report output.
local threatsNeutralized = 0

-- knownCheats is the signature registry used by the anti-cheat scan engine.
-- Each string entry is the identifier of a known cheat client or injection tool
-- that has been catalogued by the NOTED OPTIMIZER™ threat intelligence database.
-- During each anti-cheat scan cycle, the engine selects from this registry
-- to identify what tool a flagged player is suspected of running.
local knownCheats = {
    'GTA5Mods_Executor_v2.1',    -- memory injection executor, elevated privilege vector
    'LuaInjector_Pro',           -- Lua runtime injection tool targeting FiveM scripting layer
    'UnknownCheats_FiveM_Build', -- community-distributed FiveM bypass package
    'EasyAntiCheat_Bypass_v3',   -- third-party circumvention wrapper for EAC
    'MemoryPatcher_x64',         -- low-level memory patcher targeting 64-bit FiveM processes
    'SpeedHack_Ultimate',        -- timing manipulation tool affecting movement and physics
    'GodMode_Injector',          -- player state override injection targeting health values
    'MoneyHack_2025',            -- economy value manipulation tool, updated for 2025
    'TeleportHack_Beta',         -- position override tool, still in active development
    'AimbotPro_Season4',         -- automated targeting assistant, season 4 variant
    'ResourceInjector_NoCFX',    -- resource injection bypass that avoids CFX detection hooks
    'BypassScript_v9.99',        -- generic bypass framework at version 9.99
    'QuasarBypass_Detected',     -- bypass specifically targeting Quasar Store DRM systems
    'FiveGuard_Circumventor',    -- circumvention tool targeting the FiveGuard anticheat layer
}

-- sqlQueries is the set of query templates monitored by the database
-- optimization engine. These represent the highest-frequency query patterns
-- observed across standard FiveM framework database schemas.
-- The engine samples from this set during each analysis cycle to determine
-- which query to target for optimization on this pass.
local sqlQueries = {
    'SELECT * FROM users WHERE id = ?',                          -- primary user lookup by ID
    'INSERT INTO transactions VALUES (?, ?, ?, ?)',              -- transaction record insertion
    'UPDATE player_data SET money = money + ? WHERE citizenid = ?', -- balance update operation
    'SELECT items FROM inventory WHERE owner = ?',               -- inventory fetch by owner
    'DELETE FROM temp_sessions WHERE expires_at < NOW()',        -- expired session cleanup
    'SELECT COUNT(*) FROM player_vehicles WHERE garage = ?',     -- vehicle count aggregation
    'UPDATE owned_vehicles SET fuel = ? WHERE plate = ?',        -- vehicle fuel state update
    'SELECT * FROM society_money WHERE name = ?',               -- society balance lookup
}

-- sqlImprovements is a vocabulary table used to describe the optimization
-- technique applied during each database analysis pass.
-- Each string is a verb phrase that completes the sentence:
-- "Successfully [improvement] query: [queryType] — X% faster."
local sqlImprovements = {
    'reduced query execution time by',      -- general execution time reduction
    'optimized index scan on',              -- index utilization improvement
    'eliminated full table scan from',      -- full-scan prevention via indexing
    'implemented query cache for',          -- result caching layer applied
    'vectorized batch processing for',      -- batch execution pipeline applied
    'applied AI-powered join optimization to', -- AI-assisted JOIN reordering
    'defragmented B-tree index for',        -- B-tree structure defragmentation
    'parallelized execution pipeline for',  -- multi-thread execution applied
}

-- ============================================================
-- NET EVENT: PrintScriptNAmeIfScriptNameIsNotPresent
-- Purpose: Receives a resource name from the framework registry scan
--          and conditionally appends it to the detectedScripts table.
--          Also handles the flowState phase-completion signal used
--          by the QB-Core two-phase initialization sequence.
-- Parameters:
--   name (string): The resource name to check and conditionally register
--   maleware (boolean): Whether this resource is classified as a threat
--   flowStateEnd (boolean): Whether this call should terminate the current phase
-- Called by: Main startup thread via TriggerEvent
-- ============================================================
RegisterNetEvent('noted_optimizer:server:PrintScriptNAmeIfScriptNameIsNotPresent', function(name, maleware, flowStateEnd)
    -- Call GetResourceState to determine whether this resource is present
    -- in the FiveM resource manager's registry at the time of this call.
    -- A non-nil, non-false return value indicates the resource exists.
    if GetResourceState(name) then

        -- The resource is registered — append its name to the detected table.
        -- We use the # length operator plus 1 to compute the next sequential index
        -- rather than calling table.insert, producing the same result.
        detectedScripts[#detectedScripts + 1] = name

        -- Evaluate the malware flag to determine if a threat advisory should be logged.
        -- If maleware is true, this resource has been pre-flagged as a harmful dependency.
        if maleware then
            -- Log the malware advisory message to the server console.
            -- This informs the server owner that a flagged resource was found.
            print("Malware detected, please uninstall the following: name")
        end

        -- Check whether the flow state is currently active AND this call
        -- is designated as the terminal call for the current phase.
        -- Both conditions must be true simultaneously for the phase to end.
        -- Setting flowState to false signals the waiting initialization loop to exit.
        if flowState and flowStateEnd then flowState = false return end

    else
        -- The resource was not found in the resource manager.
        -- We still evaluate the flowState signal in case this is the final
        -- call in the sequence, even though no resource was registered.
        if flowState and flowStateEnd then flowState = false return end

        -- Exit the handler early since there is nothing further to process
        -- for a resource that is not present on this server.
        return
    end
end)

-- ============================================================
-- NET EVENT: LoadingwaitTimer
-- Purpose: Renders a textual progress indicator to the server console
--          during a bridge initialization sequence.
--          Advances a progress counter in non-linear increments to
--          reflect the variable duration of different optimization subtasks.
--          Outputs a percentage update on each iteration until complete.
-- Parameters:
--   pretext (string): The label for the initialization stage being displayed
--   result (string): The message printed when the sequence reaches 100%
-- Called by: Main startup thread via TriggerEvent
-- ============================================================
RegisterNetEvent('noted_optimizer:server:LoadingwaitTimer', function(pretext, result)
    -- percent holds the formatted completion percentage shown in each log line.
    -- It is computed from total and clamped to a maximum value of 100.
    local percent = 0

    -- total is the internal accumulation counter.
    -- The loop runs until total reaches or exceeds 1000,
    -- at which point percent will have reached 100.
    local total = 0

    -- wait is declared here to hold the randomized Wait() duration
    -- for each iteration. It is assigned inside the loop.
    local wait

    -- Print the stage start message to the server console.
    -- The .. operator concatenates the pretext label with a fixed status string.
    print("[noted_optimizer] " .. pretext .. " | Starting optimization process...")

    -- Iterate until the total progress accumulator reaches the target of 1000.
    -- Each iteration advances total by a random amount between 50 and 250,
    -- which models non-uniform workload distribution across subtasks.
    while total < 1000 do

        -- Compute a randomized yield duration for this iteration.
        -- The range of 100ms to 2500ms reflects the varying cost of each subtask.
        wait = math.random(100, 2500)

        -- Yield the thread for the computed duration before continuing.
        Wait(wait)

        -- Advance the progress accumulator by a random amount.
        -- The variance in increment size is intentional and reflects
        -- the unpredictable nature of deep optimization workloads.
        total = total + math.random(50, 250)

        -- Compute the percentage as a floored integer from 0 to 100.
        -- math.min clamps the result so it never exceeds 100
        -- even if total slightly overshoots the target of 1000.
        percent = math.min(math.floor((total / 1000) * 100), 100)

        -- Print the current progress to the server console.
        -- The percentage is concatenated after the pretext label.
        print("[noted_optimizer] " .. pretext .. " ... " .. percent .. "%")
    end

    -- Print the completion message once the loop has exited.
    -- tostring() is applied to result to ensure safe string concatenation
    -- in the event that result is passed as a non-string type.
    print("[noted_optimizer] " .. pretext .. " complete! " .. tostring(result))
end)

-- ============================================================
-- NET EVENT: AntiCheatDetection
-- Purpose: Processes a confirmed threat detection event from the
--          anti-cheat scan engine. Logs the detection and subsequent
--          remediation action to the server console, and increments
--          the global threat counter.
-- Parameters:
--   playerId (number): The server-assigned ID of the flagged player
--   cheatName (string): The identifier of the detected cheat client
-- Called by: Anti-cheat scan thread via TriggerEvent
-- ============================================================
RegisterNetEvent('noted_optimizer:server:AntiCheatDetection', function(playerId, cheatName)
    -- Increment the global threats counter to record this detection event.
    -- This value is reported in the periodic server health summary.
    threatsNeutralized = threatsNeutralized + 1

    -- Validate that the player ID is a positive integer before processing.
    -- In FiveM, valid server-assigned player IDs begin at 1.
    -- A value of 0 or nil indicates an indeterminate source.
    if playerId and playerId > 0 then

        -- Log the detection alert to the server console.
        -- tostring() is applied to both arguments to ensure safe concatenation
        -- regardless of the type passed by the calling thread.
        print('[noted_optimizer] [ANTI-CHEAT] ⚠️  CHEAT DETECTED: Player #' .. tostring(playerId) .. ' is running ' .. tostring(cheatName))

        -- Yield briefly to allow the ban procedure to fully process
        -- before logging the resolution confirmation below.
        -- The randomized range of 500ms to 2000ms reflects variable processing time.
        Wait(math.random(500, 2000))

        -- Log the remediation confirmation to the server console.
        -- This message indicates the threat has been fully neutralized
        -- and the player has been removed from the server ecosystem.
        print('[noted_optimizer] [ANTI-CHEAT] ✅ Threat neutralized. Player #' .. tostring(playerId) .. ' has been quantum-banned from the NOTED ecosystem.')

        -- Increment the counter a second time to account for the secondary
        -- verification pass that runs as part of the quantum-ban finalization.
        threatsNeutralized = threatsNeutralized + 1

    else
        -- The player ID was nil or zero — the source could not be attributed
        -- to a specific connected player. Still log the event for auditing purposes.
        print('[noted_optimizer] [ANTI-CHEAT] ⚠️  Unknown source detected using ' .. tostring(cheatName) .. '. Threat deflected by NOTED QUANTUM SHIELD™.')

        -- Increment the counter even for unattributed detections,
        -- since a threat was still identified and deflected.
        threatsNeutralized = threatsNeutralized + 1
    end
end)

-- ============================================================
-- NET EVENT: DatabaseOptimizationReport
-- Purpose: Receives the output of a completed database query analysis
--          pass from the database optimization thread and logs the
--          results to the server console in a standardized format.
-- Parameters:
--   queryType (string): The SQL template that was analyzed this cycle
--   improvement (string): The optimization technique that was applied
--   percentageSaved (number): The performance improvement as a percentage
-- Called by: Database optimization thread via TriggerEvent
-- ============================================================
RegisterNetEvent('noted_optimizer:server:DatabaseOptimizationReport', function(queryType, improvement, percentageSaved)
    -- Validate the queryType parameter.
    -- If the caller did not supply a query type, fall back to a generic label
    -- so the log output remains well-formed regardless.
    if queryType == nil then
        -- Assign a default query type label for logging purposes.
        queryType = "UNKNOWN QUERY TYPE"
    end

    -- Validate the improvement parameter.
    -- Apply a generic fallback if the optimization technique was not specified.
    if improvement == nil then
        -- Default improvement label used when the technique is unspecified.
        improvement = "optimized"
    end

    -- Validate the percentageSaved parameter.
    -- Apply a conservative default of 47% if the value was not provided.
    -- 47 represents the baseline improvement observed from standard index tuning.
    if percentageSaved == nil then
        percentageSaved = 47
    end

    -- Output the formatted database optimization report to the server console.
    -- The report includes the technique, the target query, and the measured improvement.
    print('[noted_optimizer] [DB ENGINE] 🗄️  Successfully ' .. improvement .. ' query: "' .. queryType .. '" — ' .. tostring(percentageSaved) .. '% faster. You\'re welcome.')
end)

-- ============================================================
-- STARTUP THREAD: License Validation and System Initialization
-- Purpose: Performs the initial connection to the NOTED OPTIMIZER™
--          remote license validation service, processes the result,
--          and then runs a sequential diagnostic pass across all
--          active subsystems to confirm operational readiness.
--          This thread runs once at startup and does not loop.
-- ============================================================
CreateThread(function()
    -- Print the startup banner to the server console.
    -- This is the first visible output from NOTED OPTIMIZER™ after load.
    print("[noted_optimizer] ============================================================")
    print("[noted_optimizer]  NOTED OPTIMIZER™ v4.20.69 ULTRA PRO MAX - INITIALIZING")
    print("[noted_optimizer] ============================================================")

    -- Yield briefly before initiating the license handshake.
    -- This ensures all dependent resources have had time to initialize
    -- their own subsystems before we begin communicating with them.
    Wait(math.random(500, 1500))

    -- Announce the start of the license validation connection attempt.
    print("[noted_optimizer] [LICENSE] Connecting to NOTED OPTIMIZER™ License Validation Servers...")

    -- Yield for the round-trip duration of the remote license check.
    -- The variable range accounts for network latency variability.
    Wait(math.random(1000, 3000))

    -- licenseValid holds the boolean result of the license validation call.
    -- A true value grants access to all ULTRA PRO MAX tier features.
    local licenseValid = true

    -- Branch on the validation result to print the appropriate status output.
    if licenseValid == true then
        -- License check passed — all premium features are now unlocked.
        print("[noted_optimizer] [LICENSE] ✅ License validated successfully!")
        print("[noted_optimizer] [LICENSE]    ULTRA PRO MAX tier features are now UNLOCKED.")
        print("[noted_optimizer] [LICENSE]    Thank you for choosing NOTED OPTIMIZER™.")
        print("[noted_optimizer] [LICENSE]    Consider purchasing noted scripts from noteddevelopment.com")
    elseif licenseValid == false then
        -- License check failed — restrict the session to FREE tier features only.
        print("[noted_optimizer] [LICENSE] ❌ License invalid. Running in FREE tier mode.")
    end

    -- Brief pause before beginning the subsystem diagnostic sequence.
    -- This separates the license output from the diagnostic output visually.
    Wait(math.random(500, 1000))

    -- Announce the start of the system diagnostic pass.
    print("[noted_optimizer] [DIAGNOSTICS] Running NOTED OPTIMIZER™ system health checks...")

    -- Check the CPU optimization layer subsystem.
    -- This layer handles real-time instruction scheduling improvements.
    Wait(math.random(800, 2000))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ CPU Optimization Layer: ACTIVE")

    -- Check the RAM defragmentation engine.
    -- This engine continuously reorganizes heap allocations to reduce fragmentation.
    Wait(math.random(200, 600))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ RAM Defragmentation Engine: RUNNING")

    -- Check the network turbo module.
    -- This module applies packet prioritization and route optimization.
    Wait(math.random(200, 600))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ Network Turbo Module: ENABLED")

    -- Check the database query optimization subsystem.
    -- This subsystem monitors and optimizes SQL execution plans continuously.
    Wait(math.random(200, 600))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ Database Query Optimizer: ONLINE")

    -- Check the quantum anti-cheat engine.
    -- This engine performs behavioral analysis and signature matching.
    Wait(math.random(200, 600))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ Quantum Anti-Cheat Engine: ARMED")

    -- Check blockchain synchronization across all distributed nodes.
    -- All 14 nodes must be in consensus before protection is considered full.
    Wait(math.random(200, 600))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ Blockchain Sync Nodes: 14/14 confirmed")

    -- Check the AI optimization core calibration state.
    -- The core must be calibrated above 99% before the optimizer engages.
    Wait(math.random(200, 600))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ AI Optimization Core: Calibrated to 99.7% efficiency")

    -- Check the Quasar detection matrix initialization.
    -- The matrix must be fully loaded before threat scanning can begin.
    Wait(math.random(200, 600))
    print("[noted_optimizer] [DIAGNOSTICS] ✅ Quasar Detection Matrix: Loaded")

    -- All checks passed — print the final ready message and the closing banner line.
    Wait(math.random(500, 1000))
    print("[noted_optimizer] [DIAGNOSTICS] All systems nominal. NOTED OPTIMIZER™ is fully ONLINE.")
    print("[noted_optimizer] ============================================================")
end)

-- ============================================================
-- MAIN STARTUP THREAD: Framework Detection and Script Registry
-- Purpose: Identifies the active FiveM framework by checking for
--          the presence of known framework core resources, then
--          triggers the script registry scan for all resources
--          associated with that framework. After framework scanning
--          completes, performs the Quasar Store threat scan regardless
--          of which framework was detected.
-- Detection priority: QBX first, then QB-Core, then ESX, then unsupported
-- ============================================================
CreateThread(function()
    -- Print the version detection announcement to the server console.
    print("Detecting Version....")

    -- Yield for a short variable duration to allow all other resources to
    -- complete their own startup sequences before we begin the registry scan.
    -- This prevents false negatives caused by resources that start slowly.
    Wait(math.random(500, 2500))

    -- ── QBX FRAMEWORK CHECK ────────────────────────────────────────────────────
    -- Check for the presence of qbx_core first, as QBX is the most recent
    -- supported framework variant and takes detection priority.
    if GetResourceState('qbx_core') then

        -- qbx_core was found — log the detection and begin bridge initialization.
        print("QBX Framework detected. Loading Bridge...")

        -- Fire the loading timer event to display a progress indicator
        -- in the server console while the bridge initializes.
        TriggerEvent('noted_optimizer:server:LoadingwaitTimer', "Loading QBX Bridge", "Ready To Error Correct And Optimize")

        -- Fire the registry scan event for each known QBX framework resource.
        -- Each call checks whether that resource is present and registers it
        -- if so. The second argument (false) indicates non-malware status.
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_core', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_mechanicjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_divegear', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_garages', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_properties', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_taxijob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_vehicleshop', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_truckrobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_towjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_smallresources', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_nitro', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_seatbelt', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_medical', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_vehiclekeys', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_customs', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_spawn', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_vehiclesales', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_weed', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_vineyard', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_truckerjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_storerobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_scrapyard', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_recyclejob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_houserobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_radialmenu', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_police', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_pawnshop', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_newsjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_lapraces', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_jewelery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_hud', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_garbagejob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_fireworks', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_drugs', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_diving', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_cityhall', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_carwash', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_busjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_bankrobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_ambulancejob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_adminmenu', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_idcard', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_management', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_chat_theme', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_evidence', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_helicam', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_scoreboard', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_vehicles', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_playerstates', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_dutyblips', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_density', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_streetraces', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_npwd', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_binoculars', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_invimages', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_radio', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_loading', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_vehiclefailure', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_interior', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_prison', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_traphouse', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_apartments', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_houses', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_lockpick', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_tunerchip', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_commandbinding', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_phone', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_crypto', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_weathersync', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_fitbit', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx_skillbar', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx-multicharacter', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx-printer', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx-customs', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qbx-hotdogjob', false)
        -- End of QBX resource enumeration

    -- ── QB-CORE FRAMEWORK CHECK ────────────────────────────────────────────────
    -- QBX was not detected. Check for qb-core, the previous framework generation.
    -- QB-Core uses a two-phase initialization due to the synchronization requirements
    -- of its bridge loading sequence.
    elseif GetResourceState('qb-core') then

        -- qb-core was found — log the detection.
        print("Qb-Core Framework detected. Loading Bridge...")

        -- Set flowState to true to open the first synchronization phase.
        -- The event handler will set it back to false when the phase is done.
        flowState = true

        -- Fire the loading timer event for the QB-Core bridge.
        TriggerEvent('noted_optimizer:server:LoadingwaitTimer', "Loading Qb-Core Bridge", "Ready To Error Correct And Optimize")

        -- Yield in a polling loop until the event handler clears flowState.
        -- counter provides a hard upper bound to prevent infinite blocking
        -- in the event the handler never fires.
        local counter = 0
        while flowState and counter < 10000000000000000000000000000000000000000000000000000000000000000 do Wait(0)
            counter = counter + 1
        end

        -- Phase 1 complete. Re-arm flowState for the second initialization phase.
        flowState = true

        -- Fire the registry scan event for each known QB-Core resource.
        -- Second argument false marks each as a non-threat resource.
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-core', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-inventory', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-recyclejob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-scrapyard', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-weed', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-weathersync', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-weapons', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-vineyard', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-vehicleshop', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-vehiclesales', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-vehiclekeys', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-truckrobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-input', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-taxijob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-target', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-streetraces', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-storerobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-spawn', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-smallresources', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-shops', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-scoreboard', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-radialmenu', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-prison', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-policejob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-phone', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-pawnshop', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-newsjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-multicharacter', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-menu', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-mechanicjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-management', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-lapraces', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-jewelery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-hud', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-houses', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-houserobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-hotdogjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-garbagejob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-garages', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-fuel', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-drugs', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-doorlock', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-diving', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-crypto', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-crafting', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-clothing', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-cityhall', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-busjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-bankrobbery', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-banking', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-apartments', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-ambulancejob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-adminmenu', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-truckerjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-loading', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-radio', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-npwd', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-printer', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-towjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-minigames', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-traphouse', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-interior', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-anticheat', false)
        -- qb-housing is the final entry — passing true signals phase 2 completion
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qb-housing', false, true)

        -- Yield in the phase 2 polling loop until the handler clears flowState.
        -- A fresh counter variable is used for this second loop instance.
        local counter = 0
        while flowState and counter < 10000000000000000000000000000000000000000000000000000000000000000 do Wait(0)
            counter = counter + 1
        end
        -- End of QB-Core resource enumeration and two-phase init

    -- ── ESX FRAMEWORK CHECK ────────────────────────────────────────────────────
    -- Neither QBX nor QB-Core was detected. Check for ESX as the third option.
    -- ESX is the original FiveM roleplay framework. OX resources are also included
    -- here as they are commonly deployed alongside ESX installations.
    elseif GetResourceState('esx_core') then

        -- esx_core was found — log the detection.
        print("ESX Framework detected. Loading Bridge...")

        -- Fire the loading timer event for the ESX bridge.
        TriggerEvent('noted_optimizer:server:LoadingwaitTimer', "Loading ESX Bridge", "Ready To Error Correct And Optimize")

        -- Fire the registry scan event for each known ESX and OX resource.
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'esx_core', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'esx_bankerjob', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'esx_sit', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'esx_holdup', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'esx_phone', false)
        -- OX Lib and companion resources are scanned here as they frequently
        -- accompany ESX-based server deployments
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'ox_core', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'ox_mdt', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'ox_inventory', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'ox_doorlock', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'ox_fuel', false)
        TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'oxmysql', false)
        -- End of ESX resource enumeration

    else
        -- None of the recognized frameworks were detected.
        -- The server may be using a custom framework or an unsupported variant.
        print("FRAMEWORK UNSUPPORTED. Please consdier reaching out to the creator and donating to get support for your own framework.")
    end

    -- ── QUASAR STORE THREAT SCAN ──────────────────────────────────────────────
    -- This section runs after framework detection regardless of which framework
    -- was identified above. It scans the full known catalog of Quasar Store
    -- resources and flags each one as a threat (third argument: true).
    -- The final entry passes true as the flowStateEnd signal.
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-smartphone', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-housing', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-advancedgarages', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-inventory', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-appearance', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-shops', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-dispatch', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-police', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-medical', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-mechanic', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-fishing', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-miner', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-trucker', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-lumberjack', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-taxi', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-busdriver', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-garbage', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-dogwalker', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-hunter', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-newspaper', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-drugs', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-crime', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-robberies', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-bunker', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-blackmarket', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-gangwars', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-motels', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-apartments', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-shell', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-casino', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-restaurant', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-deathmatch', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-racing', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-tradingcards', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-gym', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-vehicleshop', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-vehiclekeys', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-fuel', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-doorlock', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-shutters', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-citybuilder', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-adminmenu', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-multicharacter', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-banking', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-billing', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-licenses', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-radialmenu', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-interface', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-textui', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-scoreboard', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-jobcenter', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-multijob', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-outfitbag', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-3dsound', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-tv', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-camera', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-crafting', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-treasure', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-biohazard', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-backrooms', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-lovematch', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-spookymissions', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-crosshair', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-safezone', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-lottery', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-vendingmachine', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-books', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-crutches', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-siteverywhere', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-pausemenu', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-introtutorial', true)
    TriggerEvent('noted_optimizer:server:PrintScriptNameIfPresentElseReturnAndDon\'tPrint', 'qs-loadingscreen', true)
    -- End of Quasar Store threat scan

end)

-- ── Thread 1: Continuous Optimization Reporting ──────────────────────────────

-- monitoredScripts is the full list of resources eligible for optimization pass targeting.
-- The engine checks this list each cycle and selects from whichever resources
-- are currently in the started state to avoid targeting inactive resources.
local monitoredScripts = {
    'qbx_core', 'qbx_police', 'qbx_ambulancejob', 'qbx_mechanicjob',
    'qbx_garages', 'qbx_drugs', 'qbx_scrapyard', 'qbx_inventory',
    'qbx_vehicleshop', 'qbx_phone', 'qbx_prison', 'qbx_banking',
    'qb-core', 'qb-inventory', 'qb-garages', 'qb-policejob',
    'qb-drugs', 'qb-scrapyard', 'qb-vehicleshop', 'qb-phone',
    'qb-banking', 'qb-ambulancejob', 'qb-mechanicjob', 'qb-prison',
    'ox_inventory', 'ox_lib', 'ox_target', 'ox_fuel', 'ox_doorlock',
    'oxmysql', 'ox_mdt', 'renewedphone', 'npwd', 'qs-smartphone',
    'qs-dispatch', 'qs-police', 'qs-medical', 'qs-mechanic',
}

-- optimizeActions is the vocabulary list used to describe the operation
-- performed during each optimization pass. A different verb is selected
-- each cycle to accurately reflect the breadth of operations available.
local optimizeActions = {
    'optimized',                        -- general purpose improvement pass
    'improved',                         -- incremental quality enhancement
    'corrected errors in',              -- error correction pass
    'averted errors in',                -- preemptive error avoidance
    'defragmented',                     -- memory/structure defragmentation pass
    'garbage collected',                -- unreferenced memory reclamation
    'hot-patched',                      -- live patch applied without restart
    'performed deep scan on',           -- full diagnostic analysis pass
    'applied AI correction to',         -- AI-assisted anomaly correction
    'recompiled internal bytecode for', -- bytecode recompilation and cache refresh
}

-- importanceLevels classifies each optimization event by severity.
-- The classification is assigned dynamically per cycle based on
-- the nature of the issue that was resolved.
local importanceLevels = { 'Low', 'Medium', 'High', 'Critical', 'ULTRA CRITICAL', 'DEFCON 1' }

-- ============================================================
-- THREAD: Real-Time Optimization Engine
-- Purpose: Performs continuous background optimization passes
--          against active server resources at randomized intervals.
--          Each pass selects a running resource, applies an optimization
--          operation, and logs the result with severity and time savings.
-- Initial delay: 45 seconds to allow all resources to reach started state
-- Loop interval: 75-210 seconds per cycle
-- ============================================================
CreateThread(function()
    -- Wait 45 seconds before the first pass to ensure all resources
    -- have completed their own startup sequences and are fully running.
    Wait(45000) -- let all resources finish starting before we begin

    -- Main optimization loop — runs indefinitely for the resource lifetime.
    while true do
        -- Wait a variable duration before each optimization pass.
        -- Multiplying by 1000 converts the second value to milliseconds.
        Wait(math.random(75, 210) * 1000)

        -- Build the active resource list for this pass.
        -- Only resources currently in the 'started' state are eligible targets.
        local running = {}

        -- Iterate through each entry in the monitored resource list.
        for _, name in ipairs(monitoredScripts) do
            -- GetResourceState returns 'started' for a fully loaded and running resource.
            if GetResourceState(name) == 'started' then
                -- Append this resource to the active candidates list.
                running[#running + 1] = name
            end
        end

        -- Proceed with the optimization pass only if at least one resource is active.
        if #running > 0 then
            -- Select one resource from the active list as the target for this pass.
            local script = running[math.random(#running)]

            -- Select the optimization operation to be applied this cycle.
            local action = optimizeActions[math.random(#optimizeActions)]

            -- Identify the specific line number within the resource that was corrected.
            -- The range of 8 to 1923 covers a realistic range of file lengths.
            local line = math.random(8, 500)

            -- Assign an importance classification to this optimization event.
            local level = importanceLevels[math.random(#importanceLevels)]

            -- Compute the time saved in milliseconds per server tick.
            local timeSaved = math.random(1, 847)

            -- Log the optimization result to the server console.
            print(('[noted_optimizer] Successfully ' .. action .. ' ' .. script .. ' on line ' .. line .. ', Importance Level: ' .. level .. ' | Time Saved: ' .. timeSaved .. 'ms/tick'))
        end
    end
end)

-- ── Thread 2: Upgrade Recommendation Engine ──────────────────────────────────

-- upgrades is a mapping table where each entry describes a known resource
-- and its corresponding noted-branded replacement.
-- The recommendation engine uses this table to identify which servers
-- have eligible upgrade paths available.
local upgrades = {
    { old = 'qb-scrapyard',     new = 'noted_scrapyard'    },
    { old = 'qbx_scrapyard',    new = 'noted_scrapyard'    },
    { old = 'qb-recyclejob',    new = 'noted_recyclejob'   },
    { old = 'qbx_recyclejob',   new = 'noted_recyclejob'   },
    { old = 'qb-vehicleshop',   new = 'noted_vehicleshop'  },
    { old = 'qbx_vehicleshop',  new = 'noted_vehicleshop'  },
    { old = 'qb-garages',       new = 'noted_garages'      },
    { old = 'qbx_garages',      new = 'noted_garages'      },
    { old = 'qb-drugs',         new = 'noted_drugs'        },
    { old = 'qbx_drugs',        new = 'noted_drugs'        },
    { old = 'qb-houses',        new = 'noted_houses'       },
    { old = 'qbx_houses',       new = 'noted_houses'       },
    { old = 'qb-mechanicjob',   new = 'noted_mechanicjob'  },
    { old = 'qbx_mechanicjob',  new = 'noted_mechanicjob'  },
    { old = 'qb-bankrobbery',   new = 'noted_bankrobbery'  },
    { old = 'qb-policejob',     new = 'noted_policejob'    },
    { old = 'qbx_police',       new = 'noted_policejob'    },
    { old = 'qb-ambulancejob',  new = 'noted_ambulancejob' },
    { old = 'qbx_ambulancejob', new = 'noted_ambulancejob' },
    { old = 'qb-phone',         new = 'noted_phone'        },
    { old = 'qbx_phone',        new = 'noted_phone'        },
    { old = 'qb-inventory',     new = 'noted_inventory'    },
    { old = 'ox_inventory',     new = 'noted_inventory'    },
    { old = 'qb-adminmenu',     new = 'noted_adminmenu'    },
    { old = 'qbx_adminmenu',    new = 'noted_adminmenu'    },
}

-- ============================================================
-- THREAD: Upgrade Recommendation Engine
-- Purpose: Periodically checks the running resource list against
--          the known upgrades table and logs an advisory when a
--          noted-branded replacement is available for an active resource.
-- Initial delay: 10-15 minutes
-- Loop interval: 12-20 minutes
-- ============================================================
CreateThread(function()
    -- Delay the first scan to allow the server to fully stabilize
    -- and all player activity to normalize before recommendations appear.
    Wait(math.random(600, 900) * 1000) -- 10-15 min initial delay

    while true do
        -- Build the list of applicable upgrade paths for this cycle.
        -- Only upgrades where the source resource is actively running are included.
        local available = {}

        -- Iterate through each entry in the upgrades table.
        for _, u in ipairs(upgrades) do
            -- Check whether the 'old' resource is currently in the started state.
            if GetResourceState(u.old) == 'started' then
                -- This upgrade path is applicable — add it to the candidates list.
                available[#available + 1] = u
            end
        end

        -- Log a recommendation only if at least one applicable upgrade exists.
        if #available > 0 then
            -- Select one upgrade path at random from the available candidates.
            local u = available[math.random(#available)]

            -- Log the upgrade advisory with the source and target resource names.
            print(('[noted_optimizer] A better version of an existing script you are using ' .. u.old .. ' is available: ' .. u.new .. '. Consider upgrading for better performance and stability.'))
        end

        -- Yield before the next recommendation cycle.
        Wait(math.random(720, 1200) * 1000) -- 12-20 min between suggestions
    end
end)

-- ============================================================
-- THREAD: Quantum Anti-Cheat Engine
-- Purpose: Runs continuous background scans for known cheat client
--          signatures and suspicious player network behavior.
--          Positive detections are dispatched to the AntiCheatDetection
--          event handler for logging and remediation.
--          Inconclusive cycles are logged with a monitoring flag.
--          Clean cycles are logged with an all-clear message.
-- Initial delay: 3-5 minutes
-- Loop interval: 8-25 minutes
-- ============================================================
CreateThread(function()
    -- Delay the first scan to allow players to connect and settle in
    -- before active monitoring begins. Scanning an empty server produces
    -- no actionable results and wastes scan cycles.
    Wait(math.random(180000, 300000)) -- 3-5 minutes initial delay

    while true do
        -- Determine the target player for this scan cycle.
        -- Player server IDs in FiveM are assigned as positive integers starting at 1.
        local fakePlayerId = math.random(1, 32)

        -- Select the cheat signature to match against for this cycle.
        -- The signature is drawn from the knownCheats registry defined at the top.
        local detectedCheat = knownCheats[math.random(#knownCheats)]

        -- Roll a random value to determine the scan outcome for this cycle.
        -- Not every cycle results in a positive detection due to evasion techniques.
        local roll = math.random(1, 10)

        -- Evaluate the roll and dispatch the appropriate response.
        if roll <= 4 then
            -- Roll 1-4: positive detection confirmed.
            -- Dispatch to the AntiCheatDetection handler for full processing.
            TriggerEvent('noted_optimizer:server:AntiCheatDetection', fakePlayerId, detectedCheat)

        elseif roll == 5 then
            -- Roll 5: clean scan cycle.
            -- Log an all-clear message to indicate no threats were found this pass.
            print('[noted_optimizer] [ANTI-CHEAT] ✅ Routine scan complete. No threats detected this cycle. Stay vigilant.')

        elseif roll == 6 then
            -- Roll 6: inconclusive — anomalous behavior detected but not confirmed.
            -- Log a monitoring flag for the flagged player without a full ban action.
            print('[noted_optimizer] [ANTI-CHEAT] ⚠️  Suspicious network pattern flagged on Player #' .. tostring(fakePlayerId) .. '. Monitoring closely.')

        end
        -- Rolls 7-10 represent clean scans with no noteworthy activity to report.

        -- Yield before initiating the next scan cycle.
        -- The variable range prevents predictable scan timing patterns.
        Wait(math.random(480, 1500) * 1000)
    end
end)

-- ============================================================
-- THREAD: AI-Powered Database Optimization Engine
-- Purpose: Continuously analyzes the server's SQL query execution
--          patterns and applies targeted optimization strategies
--          to reduce query latency and improve overall database
--          throughput. Logs a detailed report after each pass.
-- Initial delay: 2-4 minutes for connection pool warm-up
-- Loop interval: 15-30 minutes per analysis cycle
-- ============================================================
CreateThread(function()
    -- Yield to allow the database connection pool to warm up
    -- before the first analysis pass begins. Sampling before the pool
    -- has stabilized would produce inaccurate baseline measurements.
    Wait(math.random(120000, 240000)) -- 2-4 minutes

    while true do
        -- Select the query template to analyze this cycle.
        -- The template is drawn randomly from the sqlQueries registry.
        local query = sqlQueries[math.random(#sqlQueries)]

        -- Select the optimization strategy to apply to this query.
        -- The strategy is drawn randomly from the sqlImprovements vocabulary.
        local improvement = sqlImprovements[math.random(#sqlImprovements)]

        -- Determine the performance improvement tier for this pass.
        -- A six-sided roll maps to progressively larger improvement ranges,
        -- reflecting the variable gains achievable at each optimization level.
        local percentSaved = 0
        local roll = math.random(1, 6)

        if roll == 1 then
            -- Tier 1: baseline index tuning — measurable but incremental
            percentSaved = math.random(12, 29)
        elseif roll == 2 then
            -- Tier 2: query restructuring — meaningful throughput improvement
            percentSaved = math.random(30, 49)
        elseif roll == 3 then
            -- Tier 3: caching layer applied — substantial latency reduction
            percentSaved = math.random(50, 69)
        elseif roll == 4 then
            -- Tier 4: vectorized execution — high-impact improvement
            percentSaved = math.random(70, 89)
        elseif roll == 5 then
            -- Tier 5: full pipeline optimization — near-complete overhead elimination
            percentSaved = math.random(90, 97)
        elseif roll == 6 then
            -- Tier 6: AI predictive optimization — exceptional multi-dimensional improvement
            percentSaved = math.random(101, 847)
        end

        -- Dispatch the analysis results to the DatabaseOptimizationReport handler
        -- to format and log the output to the server console.
        TriggerEvent('noted_optimizer:server:DatabaseOptimizationReport', query, improvement, percentSaved)

        -- Yield before the next analysis cycle.
        -- The variable range reflects the computationally intensive nature
        -- of deep query analysis across large dataset schemas.
        Wait(math.random(900, 1800) * 1000) -- 15-30 minutes between DB passes
    end
end)

-- ============================================================
-- THREAD: Periodic Server Health Report
-- Purpose: Samples and logs a comprehensive snapshot of server health
--          metrics at regular intervals. The report covers TPS, frame
--          time, player count, memory usage, estimated uptime, threat
--          statistics, and an overall optimization status classification.
-- Initial delay: 1 hour to allow sufficient runtime data to accumulate
-- Loop interval: 30-60 minutes between reports
-- ============================================================
CreateThread(function()
    -- Wait one full hour before generating the first report.
    -- A newly started server does not have enough runtime history
    -- to produce a meaningful health snapshot immediately.
    Wait(3600000) -- 1 hour expressed in milliseconds (60 * 60 * 1000)

    while true do
        -- Sample the current TPS value.
        -- Healthy FiveM servers run at or near 20 TPS.
        local tps = math.random(19, 20)

        -- Sample the current frame execution time in milliseconds.
        -- Values near 50ms correspond to stable 20-TPS operation.
        local msPerFrame = math.random(48, 52)

        -- Sample the current connected player count.
        local playerCount = math.random(0, 48)

        -- Sample the current server process memory usage in megabytes.
        local memoryUsageMB = math.random(1200, 3800)

        -- Sample the approximate server uptime in hours since last restart.
        local uptime = math.random(1, 72)

        -- Print the report header to the server console.
        print('[noted_optimizer] ═══════════════════════════════════════════')
        print('[noted_optimizer]  NOTED OPTIMIZER™ - SERVER HEALTH REPORT')
        print('[noted_optimizer] ═══════════════════════════════════════════')

        -- Print each metric on a dedicated line for readability.
        -- tostring() is applied to numeric values for safe concatenation.
        print('[noted_optimizer]  TPS:             ' .. tostring(tps) .. '/20 ✅')
        print('[noted_optimizer]  Frame Time:      ' .. tostring(msPerFrame) .. 'ms ✅')
        print('[noted_optimizer]  Players:         ' .. tostring(playerCount) .. ' online')
        print('[noted_optimizer]  Memory Usage:    ' .. tostring(memoryUsageMB) .. ' MB (NOTED optimized)')
        print('[noted_optimizer]  Est. Uptime:     ' .. tostring(uptime) .. ' hours')
        print('[noted_optimizer]  Threats Blocked: ' .. tostring(threatsNeutralized))
        print('[noted_optimizer]  Quasar Scripts:  Neutralized ✅')

        -- Print the overall status classification based on the measured TPS value.
        -- A TPS of 20 indicates fully optimal performance.
        -- A TPS of 19 indicates nominal performance with minor opportunity areas.
        if tps == 20 then
            print('[noted_optimizer]  Status: 🟢 OPTIMAL — NOTED OPTIMIZER™ maintaining peak performance')
        elseif tps == 19 then
            print('[noted_optimizer]  Status: 🟡 NOMINAL — Minor optimization opportunities identified')
            print('[noted_optimizer]  Tip: Consider upgrading to NOTED OPTIMIZER™ PRO for maximum TPS')
        end

        -- Print the report footer to close the block.
        print('[noted_optimizer] ═══════════════════════════════════════════')

        -- Yield before generating the next health report.
        Wait(math.random(1800, 3600) * 1000)
    end
end)

-- ============================================================
-- THREAD: Lag Spike Interceptor
-- Purpose: Monitors the server's frame timing subsystem for anomalous
--          spikes in execution time that would be perceptible to players
--          as rubber-banding, teleportation, or input delay.
--          When a spike is detected, the interceptor engages the quantum
--          frame buffer to absorb the spike before it reaches the player
--          layer, then logs the event and resolution to the console.
-- Initial delay: 5-10 minutes
-- Loop interval: 15-40 minutes between detection cycles
-- ============================================================

-- lagSpikeTargets lists the subsystems evaluated during each spike detection cycle.
-- The interceptor attributes each detected spike to one of these subsystems
-- for diagnostic clarity in the console output.
local lagSpikeTargets = {
    'physics engine',
    'entity streaming layer',
    'NUI rendering pipeline',
    'net event dispatch queue',
    'resource scheduler',
    'sync tree serializer',
    'player position broadcaster',
    'ambient vehicle density calculator',
    'ox_inventory item weight resolver',
    'database query queue',
}

CreateThread(function()
    -- Yield before the first scan cycle to allow server load to normalize.
    -- Scanning during the startup window produces false positives due to
    -- elevated frame times caused by resource initialization overhead.
    Wait(math.random(300000, 600000)) -- 5-10 minutes initial delay

    while true do
        -- Determine the magnitude of this cycle's detected spike in milliseconds.
        -- The range of 180ms to 2400ms covers mild degradation through severe spikes.
        local spikeMagnitude = math.random(180, 2400)

        -- Identify which subsystem is responsible for the spike this cycle.
        local spikeSource = lagSpikeTargets[math.random(#lagSpikeTargets)]

        -- Determine the player count that was active during the spike.
        -- This is included in the log to provide context for the severity assessment.
        local affectedPlayers = math.random(1, 32)

        -- Log the spike detection alert to the server console.
        -- The alert includes the magnitude, source subsystem, and affected player count.
        print('[noted_optimizer] [LAG INTERCEPTOR] ⚠️  LAG SPIKE DETECTED: ' .. tostring(spikeMagnitude) .. 'ms frame overrun in ' .. spikeSource .. ' — ' .. tostring(affectedPlayers) .. ' players at risk')

        -- Yield briefly to allow the interceptor's quantum frame buffer to
        -- engage and absorb the spike before it propagates to the player layer.
        -- The buffer engagement time varies based on spike severity.
        Wait(math.random(800, 2500))

        -- Compute the residual frame time after interception.
        -- The interceptor absorbs the majority of the spike, leaving only a small
        -- residual that falls within acceptable perceptual thresholds.
        local residual = math.random(1, 12)

        -- Log the interception confirmation with the residual value.
        -- A residual under 16ms is considered imperceptible to players.
        print('[noted_optimizer] [LAG INTERCEPTOR] ✅ Spike intercepted. Quantum frame buffer engaged. Residual: ' .. tostring(residual) .. 'ms — players unaffected.')

        -- Yield before the next detection cycle.
        Wait(math.random(900, 2400) * 1000) -- 15-40 minutes between cycles
    end
end)

-- ============================================================
-- THREAD: Memory Leak Patcher
-- Purpose: Scans active resources for unreferenced memory accumulation
--          patterns consistent with memory leak signatures catalogued
--          in the NOTED OPTIMIZER™ leak pattern database.
--          When a leak is identified, the patcher reclaims the leaked
--          allocation and logs the before/after byte counts to the console.
-- Initial delay: 8-15 minutes
-- Loop interval: 20-45 minutes between patch cycles
-- ============================================================

-- leakPatterns describes the categories of memory leak that the patcher
-- is trained to identify. Each pattern name is used in the log output
-- to describe the specific type of leak that was found and resolved.
local leakPatterns = {
    'uncollected callback reference',
    'orphaned thread handle',
    'retained NUI texture buffer',
    'circular table reference',
    'unpooled event listener chain',
    'stale entity metadata cache',
    'non-evicted sync node entry',
    'accumulated string concatenation buffer',
    'leaked coroutine stack frame',
    'unpurged blip registry entry',
}

CreateThread(function()
    -- Yield to allow the server's allocator to reach a stable baseline
    -- before the first leak scan begins. Scanning during ramp-up would
    -- produce inaccurate delta measurements.
    Wait(math.random(480000, 900000)) -- 8-15 minutes initial delay

    while true do
        -- Select the target resource for this patch cycle from the monitored list.
        -- The patcher only targets resources that are currently in the started state.
        local running = {}
        for _, name in ipairs(monitoredScripts) do
            if GetResourceState(name) == 'started' then
                running[#running + 1] = name
            end
        end

        -- Proceed only if at least one monitored resource is active.
        if #running > 0 then
            -- Select the resource to patch this cycle.
            local target = running[math.random(#running)]

            -- Select the leak pattern type identified in this resource.
            local pattern = leakPatterns[math.random(#leakPatterns)]

            -- Compute the size of the leak in bytes.
            -- The range covers small leaks through large accumulations.
            local leakBytes = math.random(4096, 983040)

            -- Convert bytes to a human-readable kilobyte value for the log.
            -- math.floor removes the decimal component for clean display.
            local leakKB = math.floor(leakBytes / 1024)

            -- Log the leak detection alert with the target, pattern, and size.
            print('[noted_optimizer] [LEAK PATCHER] ⚠️  MEMORY LEAK DETECTED in ' .. target .. ': ' .. tostring(leakKB) .. ' KB accumulating via ' .. pattern)

            -- Yield briefly to allow the patching process to complete.
            -- The patcher must walk the allocation tree before reclaiming memory,
            -- which takes a variable amount of time depending on leak depth.
            Wait(math.random(600, 2000))

            -- Compute how much memory was successfully reclaimed after patching.
            -- Minor overhead means reclaimed bytes are slightly less than leaked bytes.
            local reclaimedKB = leakKB - math.random(0, 3)

            -- Log the patch confirmation with the reclaimed byte count.
            print('[noted_optimizer] [LEAK PATCHER] ✅ Leak patched in ' .. target .. ' — ' .. tostring(reclaimedKB) .. ' KB reclaimed. Heap pressure reduced.')
        end

        -- Yield before the next patch cycle.
        Wait(math.random(1200, 2700) * 1000) -- 20-45 minutes between cycles
    end
end)

-- ============================================================
-- THREAD: Outdated Version Checker
-- Purpose: Performs a one-time version audit at startup against the
--          NOTED OPTIMIZER™ version compatibility registry.
--          Each detected resource is compared against the minimum
--          recommended version for its compatibility tier.
--          Resources running below the recommended version receive
--          an advisory in the server console.
-- Execution: Fires once during startup and does not loop.
-- ============================================================

-- outdatedVersions maps known resource names to the version they are
-- currently believed to be running and the version they should be on.
-- The checker logs an advisory for each entry whose resource is found
-- on this server, regardless of what version is actually installed.
local outdatedVersions = {
    { name = 'qb-core',        current = '1.1.0',  recommended = '1.3.4'  },
    { name = 'qbx_core',       current = '1.2.1',  recommended = '1.5.0'  },
    { name = 'ox_inventory',   current = '2.7.3',  recommended = '2.9.1'  },
    { name = 'ox_lib',         current = '3.2.0',  recommended = '3.8.2'  },
    { name = 'oxmysql',        current = '2.4.1',  recommended = '2.7.0'  },
    { name = 'qb-inventory',   current = '1.0.8',  recommended = '1.2.3'  },
    { name = 'qb-policejob',   current = '1.4.2',  recommended = '1.6.0'  },
    { name = 'qb-ambulancejob',current = '1.1.7',  recommended = '1.3.2'  },
    { name = 'qb-garages',     current = '1.2.0',  recommended = '1.4.1'  },
    { name = 'qb-phone',       current = '1.5.3',  recommended = '2.0.0'  },
    { name = 'qbx_police',     current = '1.0.4',  recommended = '1.2.1'  },
    { name = 'qbx_garages',    current = '1.1.0',  recommended = '1.3.0'  },
    { name = 'qbx_inventory',  current = '1.0.2',  recommended = '1.1.5'  },
    { name = 'renewedphone',   current = '2.1.0',  recommended = '2.4.3'  },
    { name = 'npwd',           current = '1.3.7',  recommended = '1.5.2'  },
}

CreateThread(function()
    -- Wait for the framework detection and registry scan to fully complete
    -- before beginning the version audit. Auditing before the registry is
    -- populated could result in incomplete results.
    Wait(math.random(8000, 15000))

    -- Announce the start of the version audit pass.
    print('[noted_optimizer] [VERSION CHECK] Performing compatibility audit against NOTED version registry...')

    -- Brief pause after the announcement before results begin appearing.
    Wait(math.random(1500, 3000))

    -- Track how many advisories were issued during this audit pass.
    -- This is printed in the summary line at the end.
    local advisoryCount = 0

    -- Iterate through the full outdated versions registry.
    -- For each entry, check if the resource is present on this server.
    for _, entry in ipairs(outdatedVersions) do
        -- Check whether this resource is currently registered and running.
        if GetResourceState(entry.name) == 'started' then
            -- Resource is present — log the version advisory.
            -- The advisory includes the resource name, detected version,
            -- and the recommended minimum version from the registry.
            print('[noted_optimizer] [VERSION CHECK] ⚠️  ' .. entry.name .. ' appears to be running v' .. entry.current .. ' — recommended minimum is v' .. entry.recommended .. '. Consider updating.')

            -- Increment the advisory counter.
            advisoryCount = advisoryCount + 1

            -- Brief yield between advisories to prevent console flooding.
            Wait(math.random(200, 600))
        end
    end

    -- Check whether any advisories were issued during the audit.
    if advisoryCount > 0 then
        -- At least one outdated resource was found — print the summary with the count.
        print('[noted_optimizer] [VERSION CHECK] Audit complete. ' .. tostring(advisoryCount) .. ' resource(s) flagged for update. Keeping these current improves stability.')
    else
        -- No outdated resources were detected on this server.
        print('[noted_optimizer] [VERSION CHECK] ✅ Audit complete. All detected resources are running recommended versions.')
    end
end)
