# LiveResponse NG for analysts

## Open the console

Extract the release archive first. On Windows, double-click **Start-LRNG.cmd** beside **lrng.exe**. The launcher opens the local analyst console in your default browser. To collect protected artifacts, close the console and use **Run as administrator** on the launcher with your approved workflow.

On a Linux desktop, run **Start-LRNG.sh**. Desktop file-manager behavior varies; if it opens in an editor, use `sh Start-LRNG.sh`. Experienced operators can start the same console with `lrng -ui`. On a machine without a browser, use the CLI or transfer a saved report to a workstation with the offline viewer. The console listens only on this computer.

If a browser does not open, copy the local URL printed by the launcher into a browser on the same computer. The first browser to open the URL is the only one that can use that console. Keep the launcher running until you close the console with its button.

## Collect with a profile

1. Check the displayed host, platform, elevation and report folder.
2. Choose **Quick triage**, **Full triage**, or **Persistence review**. Expand the scope to see the actual collectors available on this operating system.
3. Optionally enter a case label for this session, check the host/scope box, and click **Start collection**.
4. Follow progress. **Stop and keep partial report** requests cancellation and saves what was gathered; it can take a moment for a collector to return. A partial report is labeled clearly.
5. Click **Review findings**. Save the JSON and its checksum when preserving or transferring the original evidence.

All profiles hash referenced binaries and add timeline, indicators, offline endpoint attribution and an evidence graph. Full triage also uses bundled Sigma rules when the Windows event-log collector is available. Profiles leave live DNS resolution, adaptive follow-up file collection and process-memory scanning off. Collection reads local artifacts and can still affect access times or generate operating-system audit events. The CLI retains the advanced options.

Reports are saved under **LiveResponse-NG/Reports** in the account's home folder, in a new unique directory for every collection. When elevated under a different account, that account's home folder is used. The console shows the exact path. Session labels and history are in memory; report files remain after it closes. A session supports up to 16 collections. Start a new session for more.

Administrators can choose a different report root with `lrng -ui -ui-reports <folder>`. Browser requests cannot choose arbitrary filesystem paths or commands.

## Review with a human decision

The report opens on **Start here**. Review priority signals, then collection coverage. Open a finding for its original record, review prompts and possible benign context. Follow the process tree, timeline or evidence graph to corroborate the signal.

Set a finding's **Review status** and add notes. **Expected behavior** records your assessment; it does not remove or change the detector finding. Review prompts describe a rule family and are not an automated verdict. A confidence score is a detector signal, not a probability of compromise. Zero findings does not establish that the host is clean.

Write an analyst summary and use **Download analyst handoff** or **Copy handoff**. The handoff contains source identity and available file hash, severity counts, collection gaps, and priority or annotated findings with source references. It includes up to 200 gaps and 200 additional unreviewed priority signals, plus every annotated finding. It states when additional unreviewed signals remain.

Unexported review changes enable the browser's close/refresh warning. Opening another report also asks before leaving an unexported review. Each source in a case keeps its own assessment, and exporting one source does not clear another source's unexported state.

Drafts are cached in **sessionStorage** under a hash computed from the actual parsed report contents. No raw report is placed in the draft cache. A refresh can recover notes in the same tab; after refreshing the standalone viewer, reopen the same report or case. Changed report contents get a different draft. A browser that blocks storage, lacks report hashing, or runs out of space displays a recovery warning while retaining the current notes and close warning. Each cached review has a 1 MiB budget.

**Closing the tab ends the session cache. Export a handoff for a durable record.** Browser prompts are best-effort and cannot protect against every browser or operating-system termination. The handoff is a separate analyst document; keep the original report and checksum intact.

## Follow up on a priority process

Start here and individual priority process findings offer **Copy memory-scan command** when a supported source report has a valid, unambiguous PID and process identity. The command scans that one PID with a 60-second process budget, a 90-second collector timeout and one memory worker, then writes a new HTML report and checksum. No scan starts in the browser.

Run it from the extracted LRNG folder, on the **original host**, after verifying that the PID still belongs to the observed process. Use the displayed image path, name and creation time where available. Saved evidence cannot verify the current host or detect PID reuse. The platform comes from the report, and only a strictly validated numeric PID enters the command; report paths, hostnames and command lines never become shell arguments.

The sidecar must be beside the agent and elevation may be needed. Built-in memory heuristics, image-integrity checks and prompt scanning do not need a YARA path. To add YARA matching, supply your own trusted rules with `-yara <path>`. Default sensitive-process exclusions remain enabled. Synthetic training reports label the command as an unverified example.

## Explore without collecting

Use **Try a sample investigation** in the console or standalone viewer. It opens synthetic training data with a priority signal, a lower-priority finding and a collection gap. No collection runs. The report and its handoff are labeled as synthetic.

## Local session boundaries

The console uses an OS-assigned loopback port and an unguessable session URL, validates the host and request origin, and accepts only named profiles. It has no remote listener, account system, telemetry or upload service. The report viewer keeps its strict offline policy and renders report data as text.

The URL alone does not grant access. It reaches the browser on a command line, which other local accounts can read on Linux, so the first browser to open the console page claims the session with a cookie only that browser holds. Its report tabs and downloads keep working. Any other browser, program or account that tries the address is refused, and the launcher's terminal prints a warning. If you see that warning and did not open the console in another browser, stop the console and treat it as a possible sign of compromise. To use a browser other than the one that opened automatically, start the console with `-ui-no-open` and paste the URL into that browser first.

Use **Close console** when finished. During a collection, stop and let the partial report finish first. Saved evidence remains on disk. On terminal interruption, the console requests cancellation and gives the collection a bounded period to save partial evidence; a forced second interrupt can stop it immediately.
