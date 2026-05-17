# ROPNinja

ROPNinja is a modern ROP gadget explorer for [Binary Ninja](https://binary.ninja/): fast enough to keep in your sidebar, clean enough to use in split panes, and built to feel native instead of bolted on.

It started as a transformative fork of [`binja_rop`](https://github.com/m4ul3r/binja_rop) by m4ul3r, with inspiration from [`binjago`](https://github.com/zznop/binjago). The current direction is a sidebar-first Binary Ninja workflow for exploit development, reverse engineering, CTFs, and binary triage.

## Highlights

- Native Binary Ninja sidebar widget with split-pane support.
- Uses the currently open BinaryView, so it behaves like a real workspace tool.
- Syntax-highlighted gadget rendering using Binary Ninja token colors.
- Category dropdown for all gadgets, pops, moves, calls, stack pivots, branches, and `leave`.
- Text filtering across gadget text and addresses.
- Multi-row selection with `Ctrl+C` / `Cmd+C` address copying.
- Optional short address display that strips leading zeroes.
- Optional auto-find when the sidebar or split pane opens.
- Configurable gadget backtracking, deduplication, jump gadgets, and `leave` gadgets.
- Faster bounded scanning over executable ranges, with decoded-instruction caching and cancellation support.

## Installation

Clone this repository into your Binary Ninja plugins directory:

```sh
git clone https://github.com/alessaba/ROPNinja.git "$HOME/Library/Application Support/Binary Ninja/plugins/ROPNinja"
```

Restart Binary Ninja, then open the `ROPNinja` sidebar button.

### Platform Paths

- macOS: `$HOME/Library/Application Support/Binary Ninja/plugins/ROPNinja`
- Linux: `$HOME/.binaryninja/plugins/ROPNinja`
- Windows: `%APPDATA%\Binary Ninja\plugins\ROPNinja`

## Usage

1. Open a binary in Binary Ninja.
2. Click the `ROPNinja` sidebar icon, or open it as a split pane.
3. Press `Find` to discover gadgets for the current BinaryView, or enable auto-find in settings to start searches as soon as the UI opens.
4. Filter with the dropdown or search field.
5. Select one or more rows and press `Ctrl+C` / `Cmd+C` to copy addresses.
6. Double-click a gadget to navigate to its address.

## Settings

ROPNinja registers clean `ropninja.*` settings:

- `ropninja.maxPreviousBytes`: maximum bytes to walk backward from a return instruction.
- `ropninja.deduplicateGadgets`: hide duplicate gadget text.
- `ropninja.includeBranches`: include gadgets containing `jmp` or conditional jumps.
- `ropninja.includeLeave`: include gadgets containing `leave`.
- `ropninja.stripAddressZeros`: display compact addresses in the sidebar.
- `ropninja.autoFindOnOpen`: automatically search when the sidebar or split pane is shown.

When auto-find is enabled, ROPNinja hides the manual `Find` button and gives the filter/category controls the extra room.

## Why Are Jumps And `leave` Disabled By Default?

Classic ROP hunting usually wants short, predictable chains ending in `ret`. Jump instructions are useful for JOP or special control-flow tricks, and `leave` is valuable for stack pivots, but both can add a lot of noise to everyday ROP searches.

ROPNinja keeps them off by default to preserve signal, then exposes them as explicit settings when you want the extra surface.

## Project Status

ROPNinja is actively being shaped into a first-class Binary Ninja ROP workflow. The current focus is:

- richer gadget classification,
- better copy/export formats,
- architecture-aware search improvements,
- keyboard-first table navigation,
- and tighter Binary Ninja UI integration.

## Credits

- Original project: [`binja_rop`](https://github.com/m4ul3r/binja_rop) by m4ul3r.
- Inspiration: [`binjago`](https://github.com/zznop/binjago) by zznop.
- Refactor and current direction: Alessaba.

## License

MIT. See [LICENSE](LICENSE).
