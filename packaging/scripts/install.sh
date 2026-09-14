#!/usr/bin/env sh
# bootintel-cli installer.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/bootintel/cli/main/packaging/scripts/install.sh | sh
#
# For supply-chain safety, pin to a specific release tag or commit:
#   curl -sSf https://raw.githubusercontent.com/bootintel/cli/cli-v0.1.0/packaging/scripts/install.sh | sh
#
# Env overrides:
#   BOOTINTEL_VERSION=0.1.0     pin a specific version (default: latest)
#   BOOTINTEL_INSTALL_DIR=/path override install location (default: /usr/local/bin
#                                 if writable, else ~/.local/bin)
#   BOOTINTEL_FORCE=1           overwrite an existing install without asking
#   BOOTINTEL_TARBALL=<path>    install from a local tarball (skips all network).
#                                 See "offline install" below.
#
# What it does:
#   1. Detects OS (linux/macos/windows-not-supported-yet) + arch (x86_64/aarch64).
#   2. Resolves the latest release from the GitHub API (or the pinned version).
#   3. Downloads the tarball + its SHA256 line from the release's SHA256SUMS.
#   4. Verifies the checksum before extracting.
#   5. Installs the `bootintel` binary + prints where it went.
#
# Offline install (air-gapped labs):
#   On a connected machine, download both files from
#   https://github.com/bootintel/cli/releases:
#     - bootintel-vX.Y.Z-<arch>-<os>.tar.gz
#     - SHA256SUMS
#   Copy both to the target box. Then run:
#     BOOTINTEL_TARBALL=/path/to/bootintel-vX.Y.Z-x86_64-linux.tar.gz \
#       sh install.sh
#   The script reads the SHA256SUMS file sitting next to the tarball
#   to verify integrity — no network I/O happens in this mode.
#
# What it does NOT do:
#   - No auto-update. Re-run this script to upgrade.
#   - No shell-rc modification. If install-dir isn't on your PATH, you'll get
#     a hint at the end; you decide whether to add it.
#   - No sudo prompts. If /usr/local/bin isn't writable and BOOTINTEL_INSTALL_DIR
#     isn't set, we fall back to ~/.local/bin.
#
# Verified against: dash, bash, zsh, ash (busybox), busybox sh.

set -eu

# ── Config ──────────────────────────────────────────────────────────
REPO="bootintel/cli"
BINARY="bootintel"
DEFAULT_INSTALL_DIR="/usr/local/bin"
FALLBACK_INSTALL_DIR="${HOME}/.local/bin"

# ── Colors (only when stdout is a TTY) ──────────────────────────────
if [ -t 1 ]; then
    RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m')
    BOLD=$(printf '\033[1m')
    RESET=$(printf '\033[0m')
else
    RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi

msg()  { printf '%sbootintel:%s %s\n' "${BOLD}" "${RESET}" "$*"; }
err()  { printf '%sbootintel:%s %sERROR%s %s\n' "${BOLD}" "${RESET}" "${RED}" "${RESET}" "$*" >&2; exit 1; }
warn() { printf '%sbootintel:%s %swarning%s %s\n' "${BOLD}" "${RESET}" "${YELLOW}" "${RESET}" "$*" >&2; }
ok()   { printf '%sbootintel:%s %s%s%s\n' "${BOLD}" "${RESET}" "${GREEN}" "$*" "${RESET}"; }

# ── Detect OS + arch ────────────────────────────────────────────────
detect_platform() {
    _os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    _arch="$(uname -m)"

    case "${_os}" in
        linux)  OS="linux" ;;
        darwin) OS="macos" ;;
        mingw*|msys*|cygwin*)
            err "Windows detected. install.sh doesn't support Windows yet. Download the .zip directly:
    https://github.com/${REPO}/releases/latest
Extract bootintel.exe and put it on your PATH (e.g. C:\\Users\\<you>\\.local\\bin)."
            ;;
        *)
            err "unsupported OS: ${_os} (linux + macos only for now)"
            ;;
    esac

    case "${_arch}" in
        x86_64|amd64) ARCH="x86_64" ;;
        arm64|aarch64) ARCH="aarch64" ;;
        *)
            err "unsupported architecture: ${_arch} (x86_64 + aarch64 only)"
            ;;
    esac
}

# ── Resolve version from GH API ─────────────────────────────────────
resolve_version() {
    if [ -n "${BOOTINTEL_VERSION:-}" ]; then
        VERSION="${BOOTINTEL_VERSION#v}"
        msg "using pinned version: v${VERSION}"
        return
    fi

    msg "resolving latest release from github.com/${REPO}..."
    _api_url="https://api.github.com/repos/${REPO}/releases/latest"
    _api_json="$(fetch "${_api_url}")"
    # Look for the tag_name field, strip leading 'cli-v' or 'v'.
    VERSION="$(printf '%s' "${_api_json}" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*: *"//; s/".*//; s/^cli-v//; s/^v//')"
    if [ -z "${VERSION}" ]; then
        err "could not resolve latest version from ${_api_url}. Set BOOTINTEL_VERSION=X.Y.Z to install a specific version, or check https://github.com/${REPO}/releases"
    fi
    msg "latest: v${VERSION}"
}

# ── Pick install dir ────────────────────────────────────────────────
pick_install_dir() {
    if [ -n "${BOOTINTEL_INSTALL_DIR:-}" ]; then
        INSTALL_DIR="${BOOTINTEL_INSTALL_DIR}"
        return
    fi
    if [ -d "${DEFAULT_INSTALL_DIR}" ] && [ -w "${DEFAULT_INSTALL_DIR}" ]; then
        INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
    else
        mkdir -p "${FALLBACK_INSTALL_DIR}" 2>/dev/null || true
        INSTALL_DIR="${FALLBACK_INSTALL_DIR}"
        warn "${DEFAULT_INSTALL_DIR} not writable — installing to ${INSTALL_DIR}"
    fi
}

check_existing() {
    _existing="${INSTALL_DIR}/${BINARY}"
    if [ -e "${_existing}" ]; then
        if [ "${BOOTINTEL_FORCE:-0}" = "1" ]; then
            msg "overwriting existing ${_existing} (BOOTINTEL_FORCE=1)"
        else
            _current=$("${_existing}" --version 2>/dev/null | head -1 || echo "unknown")
            warn "already installed at ${_existing} (${_current})"
            warn "set BOOTINTEL_FORCE=1 to overwrite, or pass a different BOOTINTEL_INSTALL_DIR"
            exit 0
        fi
    fi
}

# ── Fetch helpers ───────────────────────────────────────────────────
fetch() {
    _url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "${_url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "${_url}"
    else
        err "need curl or wget on PATH"
    fi
}

fetch_to() {
    _url="$1"
    _out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -o "${_out}" "${_url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${_out}" "${_url}"
    else
        err "need curl or wget on PATH"
    fi
}

# ── Download + verify + install ─────────────────────────────────────
download_and_install() {
    ASSET="${BINARY}-v${VERSION}-${ARCH}-${OS}.tar.gz"
    RELEASE_URL="https://github.com/${REPO}/releases/download/cli-v${VERSION}"
    ASSET_URL="${RELEASE_URL}/${ASSET}"
    SUMS_URL="${RELEASE_URL}/SHA256SUMS"

    _tmp="$(mktemp -d)"
    trap 'rm -rf "${_tmp}"' EXIT

    msg "downloading ${ASSET}..."
    fetch_to "${ASSET_URL}" "${_tmp}/${ASSET}"

    msg "verifying SHA256..."
    fetch_to "${SUMS_URL}" "${_tmp}/SHA256SUMS"
    verify_and_install "${_tmp}/${ASSET}" "${_tmp}/SHA256SUMS" "${ASSET}" "${_tmp}"
}

# ── Offline / air-gapped install ────────────────────────────────────
install_from_local_tarball() {
    _tarball="${BOOTINTEL_TARBALL}"
    if [ ! -f "${_tarball}" ]; then
        err "BOOTINTEL_TARBALL=${_tarball} does not exist"
    fi
    # Detect version + arch/os from the filename (bootintel-vX.Y.Z-<arch>-<os>.tar.gz).
    _fname="$(basename "${_tarball}")"
    VERSION="$(printf '%s' "${_fname}" | sed -n 's/^bootintel-v\([0-9][^-]*\)-.*/\1/p')"
    if [ -z "${VERSION}" ]; then
        err "could not parse version from filename '${_fname}' — expected bootintel-vX.Y.Z-<arch>-<os>.tar.gz"
    fi
    msg "offline mode: using tarball ${_tarball} (v${VERSION})"

    _sums=""
    _dir="$(dirname "${_tarball}")"
    if [ -f "${_dir}/SHA256SUMS" ]; then
        _sums="${_dir}/SHA256SUMS"
    elif [ -f "${_tarball}.sha256" ]; then
        _sums="${_tarball}.sha256"
    fi

    if [ -n "${_sums}" ]; then
        msg "verifying SHA256 against ${_sums}..."
        verify_and_install "${_tarball}" "${_sums}" "${_fname}" "$(mktemp -d)"
    elif [ "${BOOTINTEL_SKIP_CHECKSUM:-0}" = "1" ]; then
        warn "BOOTINTEL_SKIP_CHECKSUM=1 — installing WITHOUT verification"
        _extract_dir="$(mktemp -d)"
        tar -xzf "${_tarball}" -C "${_extract_dir}"
        _install_extracted "${_extract_dir}"
    else
        err "no SHA256SUMS or ${_tarball}.sha256 found next to tarball.
Either place SHA256SUMS (from the GH release page) alongside the tarball,
or re-run with BOOTINTEL_SKIP_CHECKSUM=1 (not recommended)."
    fi
}

verify_and_install() {
    _tarpath="$1"
    _sumspath="$2"
    _asset_name="$3"
    _tmp="$4"
    _expected="$(grep " ${_asset_name}\$" "${_sumspath}" 2>/dev/null | awk '{print $1}')"
    if [ -z "${_expected}" ]; then
        err "no SHA256 line for ${_asset_name} in ${_sumspath} — refusing to install"
    fi
    _actual="$(compute_sha256 "${_tarpath}")"
    if [ "${_actual}" != "${_expected}" ]; then
        err "SHA256 mismatch! expected ${_expected}, got ${_actual}"
    fi
    ok "checksum verified"

    msg "extracting..."
    tar -xzf "${_tarpath}" -C "${_tmp}"
    _install_extracted "${_tmp}"
}

_install_extracted() {
    _tmp="$1"
    if [ ! -f "${_tmp}/${BINARY}" ]; then
        err "expected ${BINARY} inside tarball but it's missing"
    fi
    mkdir -p "${INSTALL_DIR}"
    mv "${_tmp}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    chmod +x "${INSTALL_DIR}/${BINARY}"
    ok "installed ${BINARY} v${VERSION} → ${INSTALL_DIR}/${BINARY}"
}

compute_sha256() {
    _file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${_file}" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${_file}" | awk '{print $1}'
    else
        err "need sha256sum or shasum on PATH"
    fi
}

# ── Post-install hint ───────────────────────────────────────────────
path_hint() {
    case ":${PATH}:" in
        *:"${INSTALL_DIR}":*) : ;;
        *)
            warn "${INSTALL_DIR} is not on your PATH."
            warn "add this line to your shell config (~/.bashrc, ~/.zshrc, etc.):"
            printf '\n    export PATH="%s:$PATH"\n\n' "${INSTALL_DIR}" >&2
            ;;
    esac
    ok "try: ${BINARY} version"
}

# ── Main ────────────────────────────────────────────────────────────
main() {
    detect_platform
    msg "detected: ${OS} ${ARCH}"
    pick_install_dir
    check_existing
    if [ -n "${BOOTINTEL_TARBALL:-}" ]; then
        install_from_local_tarball
    else
        resolve_version
        download_and_install
    fi
    path_hint
}

main "$@"
