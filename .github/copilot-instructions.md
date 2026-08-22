# Network Monitoring Tool

- Keep the application standard-library-first and preserve the optional Scapy fallback.
- Keep Tkinter UI changes on the main thread; worker threads communicate with `queue.Queue`.
- Run the focused tests with `python -m unittest discover -s tests`.
