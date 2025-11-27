# Repository Guidelines

## Project Structure & Module Organization
- This tree follows the Linux kernel layout; platform sources live under `arch/arm` and `arch/arm64`, with Banana Pi board device trees in `arch/arm/boot/dts/mediatek` and `arch/arm64/boot/dts/mediatek` or `rockchip`.
- Board defconfigs are in `arch/<arch>/configs` (e.g., `mt7622_bpi-r64_defconfig`, `mt7986a_bpi-r3_defconfig`).
- Helper scripts and packaging logic are in `build.sh`, `build.conf`, and `utils/`; documentation mirrors upstream under `Documentation/`.

## Build, Test, and Development Commands
- Configure for a board: `board=bpi-r3 ./build.sh importconfig` (uses the matching defconfig). Add `builddir=/tmp/out` in `build.conf` to separate outputs.
- Build kernel and dtbs: `./build.sh build` (respects `ARCH`, `CROSS_COMPILE`, `LOCALVERSION`; uses all CPUs). Typical artifacts land in `arch/<arch>/boot/` and the working dir.
- Adjust config: `./build.sh config` for `menuconfig`; `./build.sh dtbs_check` to validate DTS bindings; `./build.sh clean` to remove build outputs.
- Package or deploy: `./build.sh pack` (SD card layout), `./build.sh deb`/`pack_debs` (Debian packages), `./build.sh install` (copy to mounted boot media), `./build.sh upload` (push to TFTP defined in `build.conf`).

## Coding Style & Naming Conventions
- Follow kernel CodingStyle: tabs, 8-width indents, `snake_case` for C identifiers, `lowercase-with-dashes.dts` for device trees. Keep includes sorted and prefer `pr_*` logging.
- Run `scripts/checkpatch.pl --strict` on patches; avoid trailing whitespace and long lines unless required by tables.
- Keep defconfig and DTS names aligned with board IDs (`bpi-r3`, `bpi-r4`, `bpi-r64`, `bpi-r2pro`).

## Testing Guidelines
- Run fast structural checks before submitting: `./build.sh dtbs_check` and `make ARCH=arm64 kselftest` (or `ARCH=arm` for R2 targets) when available.
- For packaging flows, boot-test SD or TFTP images on the target board and confirm `modules_install` results in `/lib/modules/<version>` matching the built kernel.

## Commit & Pull Request Guidelines
- Use concise, present-tense subjects (~72 chars) referencing subsystem/board (e.g., `arm64: dts: mt7986: fix r3 spi pinmux`).
- In the body, describe motivation, hardware tested (board revision, peripherals), and commands used (`./build.sh build`, `dtbs_check`, kselftest).
- PRs should link related issues or mailing list threads, include boot/test notes, and attach relevant logs or dmesg snippets when touching drivers or DTS files.
