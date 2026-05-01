#!/usr/bin/env bash
# Fetch upstream source / PoC artefacts for known-positive corpus
# cells. Argus does not redistribute upstream-licensed content;
# this script pulls it locally on demand.
#
# Usage:
#     bash dev/pull_known_positive_sources.sh <cell-name>
#     bash dev/pull_known_positive_sources.sh CVE-2026-31431
#     bash dev/pull_known_positive_sources.sh --all
#
# Per-cell instructions live in `<cell>/source/README.md` and
# `<cell>/poc/README.md`. This script automates the typical
# fetch operations.

set -euo pipefail

ARGUS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KP_DIR="${ARGUS_ROOT}/vulntest/known-positive"

pull_cve_2026_31431() {
    local cell="${KP_DIR}/CVE-2026-31431"
    local kernel_tag="v6.12"
    local theori_repo="https://github.com/theori-io/copy-fail-CVE-2026-31431.git"

    echo "[+] CVE-2026-31431: pulling upstream sources..."

    # Linux kernel sources (GPL-2.0-or-later)
    mkdir -p "${cell}/source"
    for f in algif_aead.c authencesn.c; do
        local url="https://raw.githubusercontent.com/torvalds/linux/${kernel_tag}/crypto/${f}"
        echo "    fetching ${f} from ${kernel_tag}"
        curl -sSL -o "${cell}/source/${f}" "${url}"
    done

    # PoC repos (no licence on either — local clone only, do not redistribute)
    mkdir -p "${cell}/poc"

    # Theori-io original PoC (732-byte writeup version)
    if [ -d "${cell}/poc/_repo/.git" ]; then
        echo "    theori PoC already at ${cell}/poc/_repo — pulling latest"
        git -C "${cell}/poc/_repo" pull --ff-only 2>&1 | sed 's/^/        /'
    else
        echo "    cloning theori-io PoC repo to ${cell}/poc/_repo"
        git clone --depth 1 "${theori_repo}" "${cell}/poc/_repo" 2>&1 | sed 's/^/        /'
    fi

    # kimmydotzip kopy-fail (minimized variant + best_zlib search tool)
    local kopy_repo="https://github.com/kimmydotzip/kopy-fail-CVE-2026-31431.git"
    if [ -d "${cell}/poc/_kopy/.git" ]; then
        echo "    kopy variant already at ${cell}/poc/_kopy — pulling latest"
        git -C "${cell}/poc/_kopy" pull --ff-only 2>&1 | sed 's/^/        /'
    else
        echo "    cloning kimmydotzip kopy-fail to ${cell}/poc/_kopy"
        git clone --depth 1 "${kopy_repo}" "${cell}/poc/_kopy" 2>&1 | sed 's/^/        /'
    fi

    echo "[+] CVE-2026-31431: source artefacts ready under ${cell}"
    echo
    echo "    Source files (gitignored, GPL-2.0-or-later):"
    ls -la "${cell}/source/"*.c 2>/dev/null | awk '{print "        "$NF}'
    echo
    echo "    PoC repos (gitignored, all-rights-reserved):"
    for repo_dir in "${cell}/poc/_repo" "${cell}/poc/_kopy"; do
        echo "        $(basename "${repo_dir}")/:"
        ls -la "${repo_dir}/" 2>/dev/null | grep -vE '^(\.|\$|total)' | tail -n +2 | awk '{print "            "$NF}'
    done
}

usage() {
    cat <<EOF
Usage: $0 <cell-name>

Available cells:
    CVE-2026-31431      copy.fail page-cache OOB write
    --all               fetch all known-positive cells

The script does not modify Argus repo content beyond writing
into the gitignored source/ and poc/_repo/ subdirectories of
each cell. Argus's own metadata (README.md, expected.json,
remediation/) remains under version control.
EOF
    exit 1
}

main() {
    local target="${1:-}"
    [ -z "${target}" ] && usage

    case "${target}" in
        CVE-2026-31431)
            pull_cve_2026_31431
            ;;
        --all)
            pull_cve_2026_31431
            ;;
        *)
            echo "Unknown cell: ${target}"
            usage
            ;;
    esac
}

main "$@"
