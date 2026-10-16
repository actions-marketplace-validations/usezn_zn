### Fixed
- `zn-gate check` and `zn-gate init`: when zn's own rules do not block the test `.env` file, the fix is now to install zn-gate again (`npm install -g zn-gate`), also with the zn-gate plugin; before, they asked to install the plugin that was already installed.
- `zn-gate init`: with a broken plugin next to zn's own hooks that do not work either, it now checks that the repaired hooks work before it turns the plugin off, and leaves the plugin on when they still do not.
