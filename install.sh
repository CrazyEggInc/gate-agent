#!/usr/bin/env sh

# gate-agent Installation Script
#
# Downloads the matching release archive, verifies its checksum, and installs
# gate-agent to a local bin directory.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/CrazyEggInc/gate-agent/refs/heads/master/install.sh | sh
#   VERSION=v1.2.3 curl -fsSL https://raw.githubusercontent.com/CrazyEggInc/gate-agent/refs/tags/v1.2.3/install.sh | sh
#   GATE_AGENT_INSTALL_DIR=/usr/local/bin curl -fsSL install.sh | sh
#
# Environment variables:
#   VERSION                  Version to install, with or without leading v. Defaults to latest.
#   GATE_AGENT_DOWNLOAD_URL  Base GitHub release URL override for testing.
#   GATE_AGENT_INSTALL_DIR   Install directory. Defaults to ~/.local/bin.

set -eu

REPO="CrazyEggInc/gate-agent"
BIN_NAME="gate-agent"
VERSION_INPUT="${VERSION:-latest}"

print_status() {
  printf '[INFO] %s\n' "$1" >&2
}

print_success() {
  printf '[SUCCESS] %s\n' "$1" >&2
}

print_warning() {
  printf '[WARNING] %s\n' "$1" >&2
}

print_error() {
  printf '[ERROR] %s\n' "$1" >&2
}

fail() {
  print_error "$1"
  exit 1
}

normalize_version() {
  case "$VERSION_INPUT" in
    latest)
      VERSION="latest"
      ;;
    v*)
      VERSION="${VERSION_INPUT#v}"
      ;;
    *)
      VERSION="$VERSION_INPUT"
      ;;
  esac
}

detect_linux_libc() {
  if command -v getconf >/dev/null 2>&1; then
    if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
      printf '%s\n' glibc
      return 0
    fi
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd_output="$(ldd --version 2>&1 || true)"
    case "$ldd_output" in
      *musl*)
        printf '%s\n' musl
        return 0
        ;;
    esac
  fi

  printf '%s\n' unknown
}

detect_platform() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os-$arch" in
    linux-x86_64|linux-amd64)
      TARGET="linux-x64"
      linux_libc="$(detect_linux_libc)"
      case "$linux_libc" in
        musl)
          if [ "$linux_libc" = "musl" ]; then
            TARGET="linux-x64-musl"
          fi
          ;;
        glibc|unknown)
          ;;
      esac
      ;;
    darwin-arm64|darwin-aarch64)
      TARGET="macos-arm64"
      ;;
    *)
      fail "unsupported platform: $os-$arch"
      ;;
  esac

  print_status "Platform: $TARGET"
}

download_file() {
  url="$1"
  output="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$output"
  else
    fail "curl or wget is required"
  fi
}

create_install_dir() {
  bin_dir="${GATE_AGENT_INSTALL_DIR:-$HOME/.local/bin}"

  case "$bin_dir" in
    "~")
      bin_dir="$HOME"
      ;;
    "~/"*)
      bin_dir="$HOME/${bin_dir#~/}"
      ;;
  esac

  BIN_DIR="$bin_dir"

  if [ ! -d "$BIN_DIR" ]; then
    print_status "Creating install directory: $BIN_DIR"
    mkdir -p "$BIN_DIR" || fail "could not create install directory: $BIN_DIR"
  fi

  print_status "Install dir: $BIN_DIR"
}

create_temp_dir() {
  TEMP_DIR="$(mktemp -d -t gate-agent-install.XXXXXX)"
  chmod 700 "$TEMP_DIR"
  trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM HUP
}

release_urls() {
  base_url="${GATE_AGENT_DOWNLOAD_URL:-https://github.com/$REPO/releases}"

  if [ "$VERSION" = "latest" ]; then
    ARCHIVE="gate-agent-latest-$TARGET.tar.gz"
    CHECKSUMS="gate-agent-latest-sha256sums.txt"
    DOWNLOAD_URL="$base_url/latest/download"
    print_status "Version: latest"
  else
    ARCHIVE="gate-agent-v$VERSION-$TARGET.tar.gz"
    CHECKSUMS="gate-agent-v$VERSION-sha256sums.txt"
    DOWNLOAD_URL="$base_url/download/v$VERSION"
    print_status "Version: v$VERSION"
  fi
}

verify_checksum() {
  archive="$1"
  checksums="$2"
  checksum_line="$(awk -v archive="$archive" '$2 == archive { print; found = 1; exit } END { if (!found) exit 1 }' "$checksums")" || fail "checksum not found for $archive"

  if command -v shasum >/dev/null 2>&1; then
    printf '%s\n' "$checksum_line" | shasum -a 256 -c -
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "$checksum_line" | sha256sum --check -
  else
    fail "shasum or sha256sum is required"
  fi
}

install_cli() {
  archive_path="$TEMP_DIR/$ARCHIVE"
  checksums_path="$TEMP_DIR/$CHECKSUMS"
  install_path="$BIN_DIR/$BIN_NAME"

  print_status "Downloading checksum manifest"
  download_file "$DOWNLOAD_URL/$CHECKSUMS" "$checksums_path"

  print_status "Downloading gate-agent"
  download_file "$DOWNLOAD_URL/$ARCHIVE" "$archive_path"

  print_status "Verifying checksum"
  (
    cd "$TEMP_DIR"
    verify_checksum "$ARCHIVE" "$CHECKSUMS"
  )

  print_status "Extracting archive"
  tar -xzf "$archive_path" -C "$TEMP_DIR"

  if [ ! -f "$TEMP_DIR/$BIN_NAME" ]; then
    fail "could not find $BIN_NAME in downloaded archive"
  fi

  print_status "Installing to $install_path"
  mv "$TEMP_DIR/$BIN_NAME" "$install_path"
  chmod 755 "$install_path"
}

check_path() {
  case ":$PATH:" in
    *":$BIN_DIR:"*) return 0 ;;
    *) return 1 ;;
  esac
}

detect_shell_profile() {
  shell_name="$(basename "${SHELL:-}")"

  case "$shell_name" in
    bash)
      if [ -f "$HOME/.bash_profile" ]; then
        SHELL_PROFILE="$HOME/.bash_profile"
      elif [ -f "$HOME/.bashrc" ]; then
        SHELL_PROFILE="$HOME/.bashrc"
      else
        SHELL_PROFILE="$HOME/.bash_profile"
      fi
      SHELL_RELOAD_COMMAND=". \"$SHELL_PROFILE\""
      ;;
    zsh)
      SHELL_PROFILE="$HOME/.zshrc"
      SHELL_RELOAD_COMMAND=". \"$SHELL_PROFILE\""
      ;;
    fish)
      SHELL_PROFILE="$HOME/.config/fish/config.fish"
      SHELL_RELOAD_COMMAND="source \"$SHELL_PROFILE\""
      ;;
    *)
      SHELL_PROFILE="$HOME/.profile"
      SHELL_RELOAD_COMMAND=". \"$SHELL_PROFILE\""
      ;;
  esac
}

print_path_update_failure() {
  print_warning "Failed to update PATH in $SHELL_PROFILE. Add $BIN_DIR to your PATH manually."
}

setup_path() {
  detect_shell_profile

  case "$(basename "${SHELL:-}")" in
    fish)
      path_export="set -gx PATH $BIN_DIR \$PATH"
      profile_dir="$(dirname "$SHELL_PROFILE")"
      mkdir -p "$profile_dir" 2>/dev/null || { print_path_update_failure; return 1; }
      touch "$SHELL_PROFILE" 2>/dev/null || { print_path_update_failure; return 1; }
      if ! grep -qF "$path_export" "$SHELL_PROFILE" 2>/dev/null; then
        print_status "Updating shell PATH in $SHELL_PROFILE"
        printf '%s\n' "$path_export" >> "$SHELL_PROFILE" 2>/dev/null || { print_path_update_failure; return 1; }
      fi
      ;;
    *)
      path_export="export PATH=\"$BIN_DIR:\$PATH\""
      touch "$SHELL_PROFILE" 2>/dev/null || { print_path_update_failure; return 1; }
      if ! grep -qF "$path_export" "$SHELL_PROFILE" 2>/dev/null; then
        print_status "Updating shell PATH in $SHELL_PROFILE"
        {
          printf '\n'
          printf '%s\n' '# Added by gate-agent installer'
          printf '%s\n' "$path_export"
        } >> "$SHELL_PROFILE" 2>/dev/null || { print_path_update_failure; return 1; }
      fi
      ;;
  esac

  print_success "Added $BIN_DIR to PATH"
  print_warning "Restart your shell or run: $SHELL_RELOAD_COMMAND"
}

verify_installation() {
  if PATH="$BIN_DIR:$PATH" "$BIN_NAME" version >/dev/null 2>&1; then
    print_success "Installation verified"
  else
    print_warning "Install could not be verified with '$BIN_NAME version'"
  fi
}

show_next_steps() {
  printf '\n' >&2
  printf 'Next steps:\n' >&2

  if ! check_path; then
    if [ "${PATH_UPDATE_STATUS:-not_needed}" = "updated" ]; then
      printf '  1. Restart your shell or run: %s\n' "$SHELL_RELOAD_COMMAND" >&2
    else
      printf '  1. Add %s to your PATH\n' "$BIN_DIR" >&2
    fi
    printf '  2. Run %s config init\n' "$BIN_NAME" >&2
  else
    printf '  1. Run %s config init\n' "$BIN_NAME" >&2
  fi
}

main() {
  normalize_version
  detect_platform
  create_install_dir
  create_temp_dir
  release_urls
  install_cli

  PATH_UPDATE_STATUS="not_needed"
  if ! check_path; then
    if setup_path; then
      PATH_UPDATE_STATUS="updated"
    else
      PATH_UPDATE_STATUS="failed"
    fi
  fi

  verify_installation
  print_success "Installation complete"
  show_next_steps
}

main "$@"
