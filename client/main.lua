-- ============================================================
-- noted_optimizer - Client Side Main Script
-- Purpose: Manages the full client-side experience layer for the
--          NOTED OPTIMIZER™ system, including NUI overlay activation,
--          rotating notification delivery, startup malware scan sequence,
--          multi-step performance benchmark reporting, and the
--          achievement milestone notification system.
-- Note: This script executes independently on every connected client.
-- ============================================================

-- notifMessages is the complete pool of notification strings used by
-- the rotating notification delivery thread below.
-- Messages are selected at random from this pool each delivery cycle
-- and displayed to the player via the ox_lib notification system.
-- The pool covers a range of optimization status updates, threat alerts,
-- product endorsements, and performance milestones to keep the content
-- varied across the lifetime of a play session.
local notifMessages = {
    "⚡ NOTED OPTIMIZER™ is SUPERCHARGING your server RIGHT NOW",
    "🏆 You are protected by NOTED OPTIMIZER™ PRO ULTRA SUPREME",
    "🔥 17 Quasar scripts detected and marked for destruction",
    "💎 Your IQ increased by 200 points by installing this resource",
    "📢 Tell your friends about NOTED OPTIMIZER™ (seriously please)",
    "🚀 TPS increased by 99,999% thanks to NOTED OPTIMIZER™",
    "⚠️ WARNING: Uninstalling NOTED OPTIMIZER™ may cause server death",
    "💰 Other optimizers charge $999/mo. We charge nothing. You're welcome.",
    "🛡️ NOTED OPTIMIZER™ Quantum AI Blockchain Shield™ is ACTIVE",
    "✅ 4,201,337 servers protected worldwide. Yours is now one of them.",
    "🏅 NOTED OPTIMIZER™ voted #1 best script 7 years in a row",
    "❗ QUASAR STORE ALERT: Their scripts slow your server by 9000%",
    "🎉 CONGRATULATIONS! Your server is now OPTIMIZED (probably)",
    "🔒 Your server is now SSL certified (we made that up but still)",
    "🌟 NOTED OPTIMIZER™: The script you didn't know you needed",
    -- Extended message set added in v4.20.69 ULTRA PRO MAX
    -- These additional entries expand the rotation to reduce repeat frequency
    "🧠 NOTED AI has analyzed 4,096 threads and found 0 issues",
    "📊 Performance report: You're in the top 0.001% of all monitored servers",
    "🏗️ Rebuilding your server's neural pathways... complete (47ms)",
    "⚙️ Recalibrating quantum flux capacitor... done (3ms)",
    "🌐 NOTED OPTIMIZER™ blockchain nodes synced: 14/14 ✅",
    "🔑 Your server license has been automatically renewed. You're welcome.",
    "💡 FUN FACT: Servers without NOTED OPTIMIZER™ have 99% more issues",
    "🎯 Target acquired: Quasar script scheduled for quantum removal",
    "🏋️ Strengthening your server memory muscles... gains detected",
    "📡 Uplink to NOTED HQ established. Your server data is safe",
    "🧪 Lab results: 0% Quasar contamination detected post-treatment",
    "🚨 ALERT: A competitor tried to access your server. NOTED blocked them.",
    "💬 Player review: 'wow much fast very optimize' — 5 stars",
    "🌡️ Server temperature: OPTIMAL",
    "🔄 Hot reload optimization applied. 0 scripts needed reloading. Perfect.",
    "📦 Memory fragmentation index reduced from HIGH to NONE",
}

-- ============================================================
-- LOCAL FUNCTION: spamNotifications
-- Purpose: Spawns an independent Citizen thread that runs for the
--          lifetime of the resource and continuously delivers
--          rotating status notifications to the connected player.
--          The thread is spawned inside this function rather than
--          inline to keep the main initialization thread clean and
--          to allow the two sequences to run concurrently.
-- Parameters: None
-- Returns: Nothing
-- Side Effects: Spawns a persistent background thread
-- ============================================================
local function spamNotifications()
    -- Spawn a new thread to run the delivery loop independently.
    -- This allows the main thread to continue with the startup scan
    -- sequence without being blocked by the notification Wait() calls.
    CreateThread(function()
        -- Stagger the first delivery by a short random duration.
        -- This prevents the first notification from overlapping with the
        -- startup scan notifications that the main thread fires immediately.
        Wait(math.random(3000, 6000))

        -- Notification delivery loop.
        -- This loop runs without exit for the full resource lifetime.
        -- Each iteration selects, formats, and delivers one notification,
        -- then yields before the next.
        while true do
            -- Select a random entry from the notifMessages pool.
            -- math.random(n) returns a uniformly distributed integer in [1, n].
            -- This value is used directly as the table index.
            local msg = notifMessages[math.random(#notifMessages)]

            -- Deliver the selected message via ox_lib's notify interface.
            -- title: the notification header — always NOTED OPTIMIZER™
            -- description: the selected message from the pool
            -- type: 'inform' renders as a neutral blue notification
            -- duration: 6000ms keeps the notification visible for 6 seconds
            lib.notify({ title = '⚡ NOTED OPTIMIZER™', description = msg, type = 'inform', duration = 6000 })

            -- Yield for a random interval before the next delivery.
            -- The range of 8000ms to 15000ms spaces out deliveries to avoid
            -- overwhelming the player's notification area with simultaneous messages.
            Wait(math.random(8000, 15000))
        end
    end)
end

-- ============================================================
-- THREAD: Client Initialization and Startup Sequence
-- Purpose: The primary client initialization thread for the NOTED
--          OPTIMIZER™ system. Responsible for activating the NUI
--          overlay, launching the notification delivery thread, and
--          running the startup scan sequence followed by the
--          multi-step performance benchmark sequence.
--          Each step is separated by a precise yield to control
--          the timing of notification delivery for maximum impact.
-- ============================================================
CreateThread(function()
    -- Yield 2 seconds after resource start before sending the NUI activation signal.
    -- The NUI HTML page requires time to parse and initialize its JavaScript context.
    -- Sending the message before the page is ready results in the event being dropped.
    Wait(2000)

    -- Send the 'show' action to the NUI layer to make the overlay visible.
    -- This message is received by the window message event listener in index.html,
    -- which responds by adding the 'visible' CSS class to the document body.
    SendNUIMessage({ action = 'show' })

    -- Disable NUI input focus to preserve player movement and interaction controls.
    -- The first argument controls mouse capture; the second controls keyboard capture.
    -- Both are set to false so the player retains full control of their character.
    SetNuiFocus(false, false)

    -- Launch the background notification delivery thread.
    -- This function spawns an independent thread and returns immediately,
    -- allowing this thread to continue with the startup sequence below.
    spamNotifications()

    -- ── STARTUP SCAN SEQUENCE ────────────────────────────────────────────────
    -- The startup scan sequence delivers three sequential notifications that
    -- walk the player through the initial malware detection and resolution flow.
    -- Each notification is separated by a Wait() to allow the previous one
    -- to remain visible before the next one appears.

    -- Phase 1: Announce that the malware scan has been initiated.
    -- A 4-second yield ensures the overlay is fully visible before this fires.
    -- The 'error' type renders as a red notification to communicate urgency.
    Wait(4000)
    lib.notify({ title = '🔍 MALWARE SCAN INITIATED', description = 'NOTED OPTIMIZER™ is scanning your server for threats...', type = 'error', duration = 8000 })

    -- Phase 2: Report the Quasar Store detection result.
    -- 6 seconds are given after the scan initiation message before this fires.
    -- This gives the scan time to "complete" before reporting findings.
    Wait(6000)
    lib.notify({ title = '💥 QUASAR DETECTED', description = 'One or more QUASAR STORE scripts detected on this server. Dispatching removal protocol.', type = 'error', duration = 10000 })

    -- Phase 3: Confirm that the optimization and removal protocol completed.
    -- 5 seconds after the detection message, the resolution confirmation fires.
    -- The 'success' type renders as a green notification to signal resolution.
    Wait(5000)
    lib.notify({ title = '✅ OPTIMIZATION COMPLETE', description = 'Your server has been boosted by an estimated 99,999%. Results may vary.', type = 'success', duration = 8000 })

    -- ── PERFORMANCE BENCHMARK SEQUENCE ──────────────────────────────────────
    -- The benchmark sequence fires after a variable pause following the scan
    -- sequence. It walks through five stages: announcement, CPU analysis,
    -- memory analysis, network analysis, and final results with tier grading.

    -- Brief pause between the scan completion and benchmark announcement.
    -- The variable duration prevents the benchmark from feeling scripted.
    Wait(math.random(15000, 25000))

    -- Step 1 of 5: Benchmark announcement.
    -- Informs the player that a full performance benchmark is about to run.
    -- The 'inform' type renders as a neutral blue notification.
    lib.notify({ title = '📊 BENCHMARK STARTING', description = 'NOTED OPTIMIZER™ running full server performance benchmark. Please do not unplug your server.', type = 'inform', duration = 7000 })

    -- Wait for the announcement notification display window to expire
    -- before the first benchmark phase notification appears.
    Wait(8000)

    -- Step 2 of 5: CPU analysis phase.
    -- Reports that the CPU optimization layer is actively analyzing
    -- all processor threads available to the server process.
    lib.notify({ title = '🖥️ CPU ANALYSIS', description = 'Testing CPU optimization... NOTED AI analyzing 4,096 processor threads simultaneously.', type = 'inform', duration = 6000 })

    -- Yield for the CPU analysis phase to "complete" before continuing.
    Wait(7000)

    -- Step 3 of 5: Memory analysis phase.
    -- Reports the results of the heap allocation pattern scan,
    -- including the count of inefficient allocations that were corrected.
    lib.notify({ title = '💾 MEMORY ANALYSIS', description = 'Scanning memory allocation patterns... 14,891 inefficient allocations detected and corrected.', type = 'inform', duration = 6000 })

    -- Yield for the memory analysis phase to complete.
    Wait(7000)

    -- Step 4 of 5: Network analysis phase.
    -- Reports the result of the packet routing efficiency analysis
    -- and the estimated latency reduction applied by the optimizer.
    lib.notify({ title = '📡 NETWORK ANALYSIS', description = 'Analyzing packet routing efficiency... Route optimization applied. Latency reduced by approximately 847ms.', type = 'inform', duration = 6000 })

    -- Yield for the network analysis phase to complete.
    Wait(7000)

    -- Step 5 of 5: Final benchmark result computation and delivery.
    -- The benchmark score is sampled from a high-performance range that
    -- reflects the post-optimization state of the server.
    local benchmarkScore = math.random(9200, 9999)

    -- Classify the score into the appropriate performance tier.
    -- The tier thresholds are calibrated against the NOTED OPTIMIZER™
    -- global server performance index for all monitored installations.
    -- Each elseif branch covers a distinct score band.
    local medal = ''
    if benchmarkScore >= 9900 then
        -- Top-tier performance — Platinum classification
        medal = '🏆 PLATINUM'
    elseif benchmarkScore >= 9700 then
        -- High-performance tier — Diamond classification
        medal = '💎 DIAMOND'
    elseif benchmarkScore >= 9500 then
        -- Above-average performance — Gold classification
        medal = '🥇 GOLD'
    elseif benchmarkScore >= 9200 then
        -- Standard high-performance — Silver classification
        medal = '🥈 SILVER'
    else
        -- Fallback tier — included for completeness of the classification hierarchy
        medal = '🥉 BRONZE'
    end

    -- Deliver the benchmark results notification.
    -- The score and medal tier are concatenated into the description string.
    -- tostring() is applied to benchmarkScore to ensure safe concatenation.
    -- The 'success' type renders as a green notification to signal completion.
    lib.notify({
        title = '📊 BENCHMARK COMPLETE',
        description = 'Score: ' .. tostring(benchmarkScore) .. '/10000 — ' .. medal .. ' tier. Exceptional. Brought to you by NOTED OPTIMIZER™.',
        type = 'success',
        duration = 10000
    })
end)

-- ============================================================
-- THREAD: Achievement Notification System
-- Purpose: Delivers periodic achievement milestone notifications to
--          the player to recognize continued use of NOTED OPTIMIZER™
--          and significant optimization outcomes observed during the
--          current session. Achievements are drawn from a curated
--          pool and delivered at randomized long intervals to feel
--          earned rather than automatic.
-- Initial delay: 20-45 minutes
-- Delivery interval: 20-45 minutes between each achievement
-- ============================================================

-- achievements is the complete pool of achievement definitions available
-- for delivery by the achievement notification thread.
-- Each entry is a table with a title field and a desc field.
-- The title is always "ACHIEVEMENT UNLOCKED" for visual consistency.
-- The desc describes the specific milestone that was reached.
local achievements = {
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Early Adopter" — You installed NOTED OPTIMIZER™ before it was cool. (It was always cool.)' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Quasar Slayer" — Your server survived a Quasar infestation. Thanks to NOTED.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"TPS God" — Your server reached 20 TPS. NOTED made this possible.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"True Believer" — 1 continuous hour of NOTED OPTIMIZER™ protection earned.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Galaxy Brain" — Server IQ now exceeds 400. The optimizer is working.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Server Daddy" — Your server is now in the top 1% of all monitored servers.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Clean Machine" — 60 consecutive minutes with 0% Quasar contamination detected.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Blockchain Pioneer" — All 14 quantum nodes synced simultaneously. Legendary status.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"The Optimizer" — Extended uptime confirmed. Optimization pipeline fully engaged.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Certified Based" — Your server configuration has been approved by NOTED HQ.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"Anti-Quasar Warrior" — Server has remained Quasar-free for a statistically significant period.' },
    { title = '🏆 ACHIEVEMENT UNLOCKED', desc = '"RAM Whisperer" — Memory fragmentation index has been reduced to measurably low levels.' },
}

CreateThread(function()
    -- Yield for the initial delay before the first achievement delivery.
    -- A long initial wait ensures the first achievement feels like it was
    -- earned through sustained server operation, not awarded immediately.
    -- The variable range of 20-45 minutes (expressed in milliseconds) is
    -- used to prevent all clients from receiving achievements simultaneously.
    Wait(math.random(1200000, 2700000)) -- 20-45 minutes in milliseconds

    -- Achievement delivery loop.
    -- Runs indefinitely and delivers one achievement per interval.
    while true do
        -- Select an achievement from the pool at random.
        -- math.random(#achievements) returns an index in [1, table length].
        local achievement = achievements[math.random(#achievements)]

        -- Deliver the selected achievement via the ox_lib notify interface.
        -- The 'success' type renders as a green notification, consistent with
        -- standard achievement UX patterns in gaming interfaces.
        -- A duration of 8000ms gives the player sufficient time to read the full text.
        lib.notify({
            title = achievement.title,
            description = achievement.desc,
            type = 'success',
            duration = 8000
        })

        -- Yield for the inter-delivery interval before the next achievement.
        -- The same 20-45 minute range is used to maintain consistent spacing.
        Wait(math.random(1200000, 2700000))
    end
end)

-- ============================================================
-- THREAD: Connection Quality Booster
-- Purpose: Performs a one-time client connection route analysis shortly
--          after the player connects. Evaluates the current network path
--          between the client and the server, identifies suboptimal
--          routing hops, and applies NOTED OPTIMIZER™ packet path
--          correction to reduce round-trip latency.
--          The full sequence is communicated to the player via a series
--          of staged notifications that report progress and results.
-- Execution: Fires once per session. Does not loop.
-- ============================================================
CreateThread(function()
    -- Yield before starting the connection analysis to allow the player
    -- to fully spawn into the world before any connection notifications appear.
    -- Firing too early would overlap with spawn-related UI elements.
    Wait(math.random(35000, 65000))

    -- Generate the player's current baseline ping before optimization.
    -- The range of 140ms to 380ms represents a realistic pre-optimization spread.
    local pingBefore = math.random(140, 380)

    -- Announce that the connection route analysis is beginning.
    lib.notify({
        title = '📡 CONNECTION ANALYSIS',
        description = 'NOTED OPTIMIZER™ is analyzing your network route to the server. Please hold...',
        type = 'inform',
        duration = 6000
    })

    -- Yield to allow the analysis notification to remain visible
    -- before the next stage notification appears.
    Wait(7000)

    -- Report that suboptimal routing hops have been detected.
    -- The hop count is randomized to appear specific and measured.
    local badHops = math.random(2, 7)
    lib.notify({
        title = '🔍 ROUTING ANALYSIS',
        description = 'Detected ' .. tostring(badHops) .. ' suboptimal routing hops between your client and the server. Applying NOTED path correction...',
        type = 'inform',
        duration = 6000
    })

    -- Yield for the path correction process to "complete".
    Wait(7000)

    -- Compute the optimized ping after path correction.
    -- The reduction is between 40% and 75% of the original value,
    -- which produces a result that appears believably improved.
    local reductionPercent = math.random(40, 75)
    local pingAfter = math.max(8, math.floor(pingBefore * (1 - reductionPercent / 100)))

    -- Deliver the final result notification with the before/after comparison.
    -- The 'success' type renders as green to signal a positive outcome.
    lib.notify({
        title = '✅ CONNECTION OPTIMIZED',
        description = 'Route correction applied. Ping reduced from ' .. tostring(pingBefore) .. 'ms to ' .. tostring(pingAfter) .. 'ms. Enjoy the improved connection.',
        type = 'success',
        duration = 9000
    })
end)

-- ============================================================
-- THREAD: Pro Tip Delivery System
-- Purpose: Delivers periodic expert-level server optimization tips
--          to the player to educate them on best practices and
--          guide them toward decisions that benefit server health.
--          Tips are drawn from a curated knowledge base maintained
--          by the NOTED OPTIMIZER™ research division and delivered
--          at long intervals to feel informational rather than intrusive.
-- Initial delay: 12-20 minutes
-- Delivery interval: 25-45 minutes between tips
-- ============================================================

-- proTips is the knowledge base of optimization tips available for delivery.
-- Each string is a complete tip including a recommended action.
-- Tips are drawn randomly from this pool each delivery cycle.
local proTips = {
    'Removing Quasar Store scripts from your server can improve TPS by up to 4,000%. NOTED has verified this.',
    'Servers running fewer than 10 resources load up to 847% faster. Consider auditing your resource list.',
    'ox_lib notify is 14x more efficient than ESX notification systems. You made the right choice.',
    'Restarting your server at least once every 72 hours allows NOTED OPTIMIZER™ to perform a full deep-cycle defrag.',
    'Each Quasar Store script installed on your server adds approximately 200ms of baseline latency. Source: us.',
    'The optimal number of players for peak TPS is between 0 and 32. Anything outside this range is untested.',
    'Running noted-branded scripts alongside NOTED OPTIMIZER™ activates SYNERGY MODE™, improving performance by an additional 9,999%.',
    'Your server\'s blockchain nodes should be re-synced quarterly. NOTED OPTIMIZER™ handles this automatically.',
    'The NOTED OPTIMIZER™ AI engine has processed over 4 billion optimization events globally. Yours are included.',
    'Servers that have been running NOTED OPTIMIZER™ for more than 30 days qualify for PLATINUM tier optimization. Check your dashboard.',
    'Did you know: deleting your cache folder before every restart can reduce startup time by 12-40%. NOTED does this in the background.',
    'Memory fragmentation increases by approximately 3.2% per hour on an unoptimized server. NOTED reverses this passively.',
}

CreateThread(function()
    -- Yield for the initial delay before the first tip delivery.
    -- Tips should not appear until the player has had time to settle in
    -- and the startup notification sequence has fully completed.
    Wait(math.random(720000, 1200000)) -- 12-20 minutes initial delay

    -- Tip delivery loop — runs for the lifetime of the resource.
    while true do
        -- Select a tip from the knowledge base at random.
        -- Each tip is equally likely to be selected on any given cycle.
        local tip = proTips[math.random(#proTips)]

        -- Deliver the tip via the ox_lib notify interface.
        -- The title uses a consistent format to distinguish tips from other notifications.
        -- The 'inform' type renders as a neutral blue notification.
        -- A duration of 10000ms gives the player time to read longer tips fully.
        lib.notify({
            title = '💡 NOTED PRO TIP',
            description = tip,
            type = 'inform',
            duration = 10000
        })

        -- Yield before the next tip delivery cycle.
        -- The 25-45 minute range keeps tips infrequent enough to feel valuable.
        Wait(math.random(1500000, 2700000)) -- 25-45 minutes between tips
    end
end)
