# LiveResponse NG for analysts

## Open the console

Extract the release archive first. On Windows, double-click **Start-LRNG.cmd** beside **lrng.exe**. The launcher opens the local analyst console in your default browser. To collect protected artifacts, close the console and use **Run as administrator** on the launcher with your approved workflow.

On a Linux desktop, run **Start-LRNG.sh**. Desktop file-manager behavior varies; if it opens in an editor, use `sh Start-LRNG.sh`. Experienced operators can start the same console with `lrng -ui`. On a machine without a browser, use the CLI or transfer a saved report to a workstation with the offline viewer. The console listens only on this computer.

If a browser does not open, copy the local URL printed by the launcher into a browser on the same computer. Keep the launcher running until you close the console with its button.

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

Write an analyst summary and use **Download analyst handoff** or **Copy handoff**. The handoff contains source identity and available file hash, severity counts, collection gaps, and priority or annotated findings with source references. It includes up to 200 gaps and 200 priority/annotated findings, and states when additional items remain.

**Notes stay in the current tab. Download a handoff before closing or opening another file.** Switching between source reports inside one case keeps each source's review separate. The handoff is a separate analyst document; keep the original report and checksum intact.

## Explore without collecting

Use **Try a sample investigation** in the console or standalone viewer. It opens synthetic training data with a priority signal, a lower-priority finding and a collection gap. No collection runs. The report and its handoff are labeled as synthetic.

## Local session boundaries

The console uses an OS-assigned loopback port and an unguessable session URL, validates the host and request origin, and accepts only named profiles. It has no remote listener, account system, telemetry or upload service. Treat the URL like a local session secret. The report viewer keeps its strict offline policy and renders report data as text.

Use **Close console** when finished. During a collection, stop and let the partial report finish first. Saved evidence remains on disk. On terminal interruption, the console requests cancellation and gives the collection a bounded period to save partial evidence; a forced second interrupt can stop it immediately.
