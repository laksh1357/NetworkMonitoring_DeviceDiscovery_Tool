# LAN Watchtower — Final Code Audit Notes

## Source reviewed
- Project archive: `NetworkMonitoring_DeviceDiscovery_Tool-main (1).zip`
- Review document: `Computer Networks Lab Submission 9 (4).pdf` (Review 1)
- Runtime observations supplied by the project team on 27 October 2026.

## Corrections made in this patched source archive

1. **Port-check eligibility:** online state is now normalized before checking whether a device can be scanned. This handles values such as `Online` and `ONLINE` consistently.
2. **Selection stability:** the device table refresh now retains the selected device when that device remains visible. This prevents a scan refresh from clearing the selected row and leaving the details pane empty.
3. **Separate selection and scan actions:** selecting/inspecting a row updates the details panel only. The `Check common ports` button now starts the scan, making the action clearer and avoiding an automatic scan on every row-selection event.
4. **CSV alignment:** export now writes eight data columns with matching headers: Hostname, IP Address, MAC Address, Vendor, Status, Latency, Open Ports, Last Seen. The UI-only Actions column is excluded. Rows are ordered by IP, and missing latency/open-port values are labelled explicitly.
5. **Regression tests:** added `tests/unit/test_desktop_export.py` to test status normalization and CSV field order/content.

## Validation performed in this environment
- `python -m compileall -q .` — passed.
- `python -m unittest discover -s tests` — **85 tests passed**.
- CSV row helper tests — passed.

## Still requires a live check on the student's Windows machine
- Launch the patched app with `python main.py` and select an online row, then click `Check common ports`.
- Export a fresh CSV and confirm each row has 8 columns aligned with the header.
- Real network discovery and port results depend on the machine, permissions, firewall, and network. The reported subnet/devices are observations from the user's own run, not reproduced by this code-only test environment.

## Report wording cautions
- Describe the topology as **inferred**, not physically verified.
- A newly observed open port is an alert/signal, not proof of malicious activity.
- Do not claim that port scanning passed until the patched GUI returns a real scan result.
- Do not claim that a CSV export passed until a freshly exported file has been opened and checked.
- Device discovery may be incomplete in unprivileged mode; unknown MAC/vendor/hostname values are valid limitations.

Only scan networks you own or have explicit permission to monitor.
