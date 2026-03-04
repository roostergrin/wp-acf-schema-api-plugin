#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_FILE="${ROOT_DIR}/acf-schema-api.php"
README_FILE="${ROOT_DIR}/README.md"
README_TXT_FILE="${ROOT_DIR}/readme.txt"
LICENSE_FILE="${ROOT_DIR}/LICENSE"
PLUGIN_SLUG="acf-schema-api"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_ROOT="${ROOT_DIR}/.build"
STAGE_DIR="${BUILD_ROOT}/${PLUGIN_SLUG}"

if [[ ! -f "${PLUGIN_FILE}" ]]; then
  echo "Plugin file not found: ${PLUGIN_FILE}" >&2
  exit 1
fi

if [[ ! -f "${README_TXT_FILE}" ]]; then
  echo "Plugin readme not found: ${README_TXT_FILE}" >&2
  exit 1
fi

VERSION="$(
  sed -n 's/^ \* Version: \(.*\)$/\1/p' "${PLUGIN_FILE}" | head -n 1 | tr -d '\r'
)"

if [[ -z "${VERSION}" ]]; then
  echo "Could not determine plugin version from ${PLUGIN_FILE}" >&2
  exit 1
fi

STABLE_TAG="$(
  sed -n 's/^Stable tag: \(.*\)$/\1/pI' "${README_TXT_FILE}" | head -n 1 | tr -d '\r'
)"

if [[ -z "${STABLE_TAG}" ]]; then
  echo "Could not determine Stable tag from ${README_TXT_FILE}" >&2
  exit 1
fi

if [[ "${STABLE_TAG}" != "${VERSION}" ]]; then
  echo "Version mismatch: plugin header is ${VERSION}, readme Stable tag is ${STABLE_TAG}" >&2
  exit 1
fi

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}" "${DIST_DIR}"

cp "${PLUGIN_FILE}" "${STAGE_DIR}/"
cp "${README_TXT_FILE}" "${STAGE_DIR}/readme.txt"
if [[ -f "${README_FILE}" ]]; then
  cp "${README_FILE}" "${STAGE_DIR}/README.md"
fi
if [[ -f "${LICENSE_FILE}" ]]; then
  cp "${LICENSE_FILE}" "${STAGE_DIR}/LICENSE"
fi

VERSIONED_ZIP="${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip"
LATEST_ZIP="${DIST_DIR}/${PLUGIN_SLUG}.zip"

rm -f "${VERSIONED_ZIP}" "${LATEST_ZIP}"
(
  cd "${BUILD_ROOT}"
  zip -rq "${VERSIONED_ZIP}" "${PLUGIN_SLUG}"
)
cp "${VERSIONED_ZIP}" "${LATEST_ZIP}"

echo "Built:"
echo "  ${VERSIONED_ZIP}"
echo "  ${LATEST_ZIP}"
