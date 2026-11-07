# pitchProx v0.44.3

- The tray icon returns automatically when Windows Explorer recreates the
  taskbar, without restarting pitchProx or interrupting proxy traffic.
- If Windows drops the icon without sending a notification, the next change to
  the traffic graph can restore it. An unchanged icon does not trigger periodic
  checks against Explorer.
- The README documents how to open or re-enable WebUI when the tray is
  unavailable.
