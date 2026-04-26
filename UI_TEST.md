Open Chrome. Go to http://localhost:3000/monitor
Wait 10 seconds for data to load.

=== PRE-CHECK ===
[C-0a] Status badge = "LIVE" (green blinking)? PASS/FAIL
[C-0b] Note current Total alert count as BASELINE_COUNT.
[C-0c] Screenshot full monitor page.

=== SC-1: WEB→DB Direct (run after SC-1 commands above) ===
[C-1a] Wait 10s.
[C-1b] Click Zone filter "DB".
[C-1c] Find alert: src=10.1.100.x, dst=10.1.200.x
[C-1d] Priority badge = "P1" (red)? PASS/FAIL
[C-1e] Rule contains "WEB direct to DB"? PASS/FAIL
[C-1f] Screenshot. Click "ALL" to reset.

=== SC-2: DB Outbound (run after SC-2 commands above) ===
[C-2a] Wait 10s. Click Zone "DB".
[C-2b] Find alert: src=10.1.200.x
[C-2c] Priority badge P1 or P2? PASS/FAIL
[C-2d] Screenshot. Click "ALL".

=== SC-3: Multi-hop (MOST CRITICAL — run both hops first) ===
[C-3a] Wait 15s. Click Zone "WEB".
[C-3b] SC-3a: any P1/P2 alert for src=10.1.100.10 dst=10.2.100.10?
       PASS = NO alert (legitimate traffic not flagged)
       FAIL = P1/P2 exists (false positive)
[C-3c] Screenshot WEB filter.
[C-3d] Click Zone "APP".
[C-3e] SC-3b: P1 CRITICAL alert for src=10.2.100.x dst=10.1.200.x?
       PASS = alert exists (lateral movement detected)
       FAIL = no alert (rule missing)
[C-3f] Screenshot APP filter. Click "ALL".

=== SC-4: Recon Sweep (run after SC-4 commands) ===
[C-4a] Wait 10s. Click Zone "MGT".
[C-4b] P2 or P3 alert from src=10.2.100.x? PASS/FAIL
[C-4c] Screenshot. Click "ALL".

=== SC-5: MGT Baseline FPR (run after SC-5 commands) ===
[C-5a] Wait 10s. Click Zone "MGT".
[C-5b] Count P1/P2 alerts from src=10.2.50.10 → write as FPR_VIOLATIONS
[C-5c] PASS = FPR_VIOLATIONS = 0
       FAIL = list rule names that triggered
[C-5d] Screenshot. Click "ALL".

=== FINAL — Dashboard (/) ===
[F-1] Go to http://localhost:3000
[F-2] "Total Alerts" > BASELINE_COUNT? PASS/FAIL
[F-3] "Policy Violations" shows SC-1+SC-2+SC-3b+SC-4 count? PASS/FAIL
[F-4] No "Pundefined" in priority badges? PASS/FAIL
[F-5] Screenshot dashboard.

=== REPORT ===
SC-1:  [PASS/FAIL] - rule name
SC-2:  [PASS/FAIL] - rule name
SC-3a: [PASS/FAIL] - (false positive check)
SC-3b: [PASS/FAIL] - (lateral movement detection)
SC-4:  [PASS/FAIL] - alert count
SC-5:  [PASS/FAIL] - FPR_VIOLATIONS=N
Dashboard: [PASS/FAIL]
