#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

#######################################
# Approov demo API test harness.
#
# Description:
#   Calls unprotected and protected endpoints of the Approov demo API,
#   validates HTTP status codes and logs complete HTTP exchanges
#   (request + response) to a timestamped log file.
#
# Dependencies:
#   - bash
#   - curl
#   - approov CLI available on PATH and configured
#
# Environment:
#     BASE_URL:
#     Base URL of the API under test. Default: http://localhost:8080
#   TOKDIR:
#     Directory where temporary token files are stored. Default: .config
#     LOGDIR=${TOKDIR}/logs, LOGFILE=${LOGDIR}/<timestamp>.log
#######################################

# Constants
readonly BASE_URL="${BASE_URL:-http://localhost:8080}"
readonly TOKDIR="${TOKDIR:-.config}"
readonly LOGDIR="${TOKDIR}/logs"
readonly LOGFILE="${LOGDIR}/$(date '+%Y-%m-%d_%H-%M-%S').log"

# Globals
# is_approov_disabled:
#   Boolean flag indicating if Approov checks appear disabled
#   based on /approov-state endpoint.
is_approov_disabled=false

# state_http_code:
#   HTTP status code from /approov-state endpoint.
state_http_code=''

#######################################
# Print error message to STDERR with timestamp.
# Globals:
#   None
# Arguments:
#   All arguments are printed as the error message.
# Outputs:
#   Writes formatted error message to STDERR.
# Returns:
#   0
#######################################
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

#######################################
# Ensure a required command exists on PATH.
# Globals:
#   None
# Arguments:
#   command name to check.
# Outputs:
#   Error message to STDERR if command is missing.
# Returns:
#   Exits the script with code 1 if the command is missing.
#######################################
requirement_check() {
  local cmd="$1"

  if ! command -v "${cmd}" >/dev/null 2>&1; then
    err "Missing required command: ${cmd}"
    exit 1
  fi
}

#######################################
# Generate an Approov token into an output file.
# Globals:
#   none
# Arguments:
#   output file path.
#   arguments passed to "approov token".
# Outputs:
#   Writes token (if generated) to the output file.
# Returns:
#   0 on success.
#   1 on failure.
#######################################
gen_token() {
  local outfile="$1"
  shift

  set +o errexit
  approov token "$@" >"${outfile}"
  local rc=$?
  set -o errexit

  if (( rc != 0 )); then
    err "Approov CLI failed: approov token $*"
    return 1
  fi

  return 0
}

#######################################
# Print test result and append full HTTP exchange to a log file.
# Globals:
#   LOGFILE
#   state_http_code
# Arguments:
#   $1 - test name.
#   $2 - expected HTTP status code.
#   $3 - actual HTTP status code.
#   $4 - full HTTP response (headers + body).
# Outputs:
#   Human-readable result to STDOUT.
#   Detailed log entry appended to LOGFILE.
# Returns:
#   0
#######################################
print_test_result() {
  local name="$1"
  local expected="$2"
  local status="$3"
  local resp="$4"

  local result="Failed"
  if [[ "${status}" == "${expected}" ]]; then
    result="Passed"
  fi

  echo "${name}: ${result}  (status: ${status}, expected: ${expected})"

  {
    echo "Test: ${name}"
    echo "Expected status: ${expected}"
    echo "Actual status:   ${status}"
    if [[ "${state_http_code:-}" == "200" ]]; then
      echo "Approov State: enabled, token checks performed."
    else
      echo "Approov State: disabled, no checks performed."
    fi
    echo
    echo "HTTP exchange:"
    echo "${resp}"
    echo
  } >>"${LOGFILE}" 2>&1
}

#######################################
# Execute a curl call for a test and evaluate the result.
# Globals:
#   LOGFILE         (written via print_test_result)
#   state_http_code (read via print_test_result for logging)
# Arguments:
#   test name.
#   expected HTTP status code.
#   arguments passed to curl.
# Outputs:
#   Short result to STDOUT, full HTTP exchange appended to LOGFILE.
# Returns:
#   0 on success, curl's exit code on failure
#######################################

run_test() {
  local name="$1"; shift
  local expected="$1"; shift

  local resp
  local status
  local curl_rc

  # -i: include headers; -s: silent
  set +o errexit
  resp="$(curl -i -s "$@")"
  curl_rc=$?
  set -o errexit

  if (( curl_rc != 0 )); then
    err "curl failed for ${name} (rc=${curl_rc})"
    return $curl_rc
  fi

  status="$(
    printf '%s\n' "${resp}" \
      | grep -m1 '^HTTP/' \
      | awk '{print $2}'
  )"

  print_test_result "${name}" "${expected}" "${status}" "${resp}"
}

main() {
  requirement_check "approov"
  requirement_check "curl"

  mkdir -p "${TOKDIR}" "${LOGDIR}"

  echo "Listing Approov API configuration:"
  approov api -list
  echo

  echo "Approov state check:"
  local state_response
  state_response="$(curl -i -s "${BASE_URL}/approov-state")"
  state_http_code="$(
    printf '%s\n' "${state_response}" \
      | grep -m1 '^HTTP/' \
      | awk '{print $2}'
  )"

  if [[ "${state_http_code}" != "200" || -z "${state_http_code}" ]]; then
    err "Failed to get Approov state from ${BASE_URL}/approov-state (status=${state_http_code:-unknown})"
    exit 1
  fi


if grep -q '"approovEnabled":true' <<<"${state_response}"; then
  echo " Approov service: ENABLED"
  is_approov_disabled=false
else
  echo " Approov service: DISABLED"
  is_approov_disabled=true
fi
echo

  # 0) Unprotected endpoint.
  run_test \
    "Unprotected request - no approov protection" \
    200 \
    "${BASE_URL}/unprotected"

  # 1) Token check (single binding).
  gen_token \
    "${TOKDIR}/approov_token_1_valid" \
    -genExample \
    example.com

  # 1.1 Valid Token.
  local expected_status=200
  run_test \
    "Token check - valid token" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_1_valid")" \
    "${BASE_URL}/token-check"

  # 1.2 Invalid Token.
  gen_token \
    "${TOKDIR}/approov_token_1_invalid" \
    -genExample \
    example.com \
    -type invalid || true

  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi

  run_test \
    "Token check - invalid token" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_1_invalid")" \
    "${BASE_URL}/token-check"

  # 2) Token Binding ["Authorization"].
  local AUTH_VAL="ExampleAuthToken=="
  export HASH_INPUT="${AUTH_VAL}"

  gen_token \
    "${TOKDIR}/approov_token_2_valid" \
    -setDataHashInToken "${HASH_INPUT}" \
    -genExample \
    example.com

  # 2.1 Valid Token.
  expected_status=200
  run_test \
    "Single Binding - valid token and header" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_valid")" \
    "${BASE_URL}/token-binding"

  # 2.2 Missing Header.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "Single Binding - missing Authorization header" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_valid")" \
    "${BASE_URL}/token-binding"

  # 2.3 Incorrect Header.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "Single Binding - incorrect Authorization header" \
    "${expected_status}" \
    -H "Authorization: BadAuthToken==" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_valid")" \
    "${BASE_URL}/token-binding"

  # 2.4 Invalid Token.
  gen_token \
    "${TOKDIR}/approov_token_2_invalid" \
    -setDataHashInToken "${HASH_INPUT}" \
    -genExample \
    example.com \
    -type invalid || true

  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "Single Binding - invalid token" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_invalid")" \
    "${BASE_URL}/token-binding"

  # 3) Token Binding ["Authorization", "Content-Digest"].
  local AUTH_VAL2="ExampleAuthToken=="
  local CD_VAL="ContentDigest=="
  export HASH_INPUT="${AUTH_VAL2}${CD_VAL}"

  gen_token \
    "${TOKDIR}/approov_token_3_valid" \
    -setDataHashInToken "${HASH_INPUT}" \
    -genExample \
    example.com

  # 3.1 Valid.
  expected_status=200
  run_test \
    "Double Binding - valid token and headers" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL2}" \
    -H "Content-Digest: ${CD_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_valid")" \
    "${BASE_URL}/token-double-binding"

  # 3.2 Missing headers.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "Double Binding - missing binding headers" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_valid")" \
    "${BASE_URL}/token-double-binding"

  # 3.3 Incorrect headers.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "Double Binding - incorrect binding headers" \
    "${expected_status}" \
    -H "Authorization: BadAuthToken==" \
    -H "Content-Digest: BadContentDigest==" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_valid")" \
    "${BASE_URL}/token-double-binding"

  # 3.4 Invalid token.
  gen_token \
    "${TOKDIR}/approov_token_3_invalid" \
    -setDataHashInToken "${HASH_INPUT}" \
    -genExample \
    example.com \
    -type invalid || true

  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "Double Binding - invalid token" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL2}" \
    -H "Content-Digest: ${CD_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_invalid")" \
    "${BASE_URL}/token-double-binding"

  echo
  echo "Full request and response details are saved in:"
  echo "  ${LOGFILE}"
}

main "$@"
