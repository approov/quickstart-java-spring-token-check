#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

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
#   BASE_URL:
#     Base URL of the API under test.
#     Default: http://localhost:8080
#
#   TOKDIR:
#     Directory where temporary token files are stored.
#     Default: .config
#
#   Tests:
#   0 - Unprotected request (no Approov protection): Access unprotected endpoint.
# 1.1 - Token check (valid token): Valid Approov token.
# 1.2 - Token check (invalid token): Invalid Approov token.
# 2.1 - Single binding (valid token + header): Valid token and correct Authorization header.
# 2.2 - Single binding (missing Authorization header): Valid token, missing Authorization.
# 2.3 - Single binding (incorrect Authorization header): Valid token, wrong Authorization.
# 2.4 - Single binding (invalid token): Invalid token, correct Authorization.
# 3.1 - Double binding (valid token + headers): Valid token, both binding headers.
# 3.2 - Double binding (missing binding headers): Valid token, missing both headers.
# 3.3 - Double binding (incorrect binding headers): Valid token, wrong headers.
# 3.4 - Double binding (invalid token): Invalid token, correct headers.
# 4.1 - token-check (no Approov header): Protected endpoint, no Approov header.
# 4.1 - token-binding (no Approov header): Protected endpoint, no Approov header.
# 4.1 - token-double-binding (no Approov header): Protected endpoint, no Approov header.
# 4.2 - unprotected (valid token only): Unprotected endpoint, valid token only.
# 4.2 - token-check (valid token only): Protected endpoint, valid token only.
# 4.2 - token-binding (valid token only): Protected endpoint, valid token only.
# 4.2 - token-double-binding (valid token only): Protected endpoint, valid token only.
# 4.3 - token-binding (valid token + Authorization): Valid single-binding token and Authorization.
# 4.3 - unprotected (valid token + Authorization): Unprotected endpoint, valid token and Authorization.
# 4.3 - token-check (valid token + Authorization): Protected endpoint, valid token and Authorization.
# 4.3 - token-double-binding (valid token + Authorization): Double-binding endpoint, valid token and Authorization.
# 4.4 - token-double-binding (valid token + two bindings): Double-binding endpoint, valid token and both headers.
# 4.4 - unprotected (valid token + two bindings): Unprotected endpoint, valid token and both headers.
# 4.4 - token-check (valid token + two bindings): Protected endpoint, valid token and both headers.
# 4.4 - token-binding (valid token + two bindings): Single-binding endpoint, valid token and both headers.
# 5.1 - Bad token (bad signature): Token with bad signature.
# 5.2 - Bad token (invalid encoding): Token with invalid encoding.
# 5.3 - Bad token (no expiry): Token with no expiry.
# 5.4 - Bad token (no expiry simulated): Simulated token with no expiry.
# 5.5 - Bad token (expired): Explicitly expired token.
# 5.6 - Missing binding with good full token: Double-binding endpoint, valid token and both headers, but token not bound.
# 5.7 - Missing Authorization with valid binding token: Double-binding endpoint, valid token and Content-Digest only.
# 5.8 - Good full token with correct binding: Double-binding endpoint, valid token and correct headers.
# 5.9 - Correct token but wrong binding headers: Double-binding endpoint, valid token and wrong headers.
#######################################

# Constants.
readonly BASE_URL="${BASE_URL:-http://localhost:8080}"
readonly TOKDIR="${TOKDIR:-.config}"
readonly LOGDIR="${TOKDIR}/logs"
readonly LOGFILE="${LOGDIR}/$(date '+%Y-%m-%d_%H-%M-%S').log"

# Globals.
# is_approov_disabled:
#   Boolean flag indicating if Approov checks appear disabled
#   based on /approov-state endpoint.
is_approov_disabled=false

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
#   None
# Arguments:
#   $1 - output file path.
#   remaining - arguments passed to "approov token".
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
    local enforced_msg
    if [[ "${is_approov_disabled}" == true ]]; then
      enforced_msg="Approov enforcement: disabled, expecting HTTP 200 on protected endpoints."
    else
      enforced_msg="Approov enforcement: enabled, token checks performed."
    fi
    echo "${enforced_msg}"
    echo
    echo "HTTP exchange:"
    echo "${resp}"
    echo
  } >>"${LOGFILE}" 2>&1
}

#######################################
# Compute expected status for protected endpoints.
#
# If Approov is disabled we expect 200 even for invalid/missing
# tokens; otherwise we expect the provided default (e.g. 401).
# Globals:
#   is_approov_disabled
# Arguments:
#   $1 - default expected status if Approov is enabled.
# Outputs:
#   Echoes effective expected status code.
# Returns:
#   0
#######################################
expected_protected_status() {
  local default_status="$1"

  if [[ "${is_approov_disabled}" == true ]]; then
    echo "200"
  else
    echo "${default_status}"
  fi
}

#######################################
# Mark a test as skipped and log the reason.
# Globals:
#   LOGFILE
# Arguments:
#   $1 - test name.
#   $2 - reason for skipping.
# Outputs:
#   Skip information to STDOUT and LOGFILE.
# Returns:
#   0
#######################################
skip_test() {
  local name="$1"
  local reason="$2"

  echo "${name}: Skipped (${reason})"

  {
    echo "Test: ${name}"
    echo "Result: SKIPPED"
    echo "Reason: ${reason}"
    echo
  } >>"${LOGFILE}" 2>&1
}

#######################################
# Execute a curl call for a test and evaluate the result.
# Globals:
#   None
# Arguments:
#   $1 - test name.
#   $2 - expected HTTP status code.
#   remaining - arguments passed to curl.
# Outputs:
#   Test result to STDOUT.
#   HTTP exchange appended to LOGFILE.
# Returns:
#   0 on success, curl return code on failure.
#######################################
run_test() {
  local name="$1"
  shift
  local expected="$1"
  shift

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
    return "${curl_rc}"
  fi

  status="$(
    echo "${resp}" \
      | grep -m1 HTTP \
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
  if [[ -z "${state_http_code}" || "${state_http_code}" != "200" ]]; then
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
    "0 - Unprotected request (no Approov protection)" \
    200 \
    "${BASE_URL}/unprotected"

  # 1) Token check (single binding).
  # 1.0 Generate valid token for /token-check.
  gen_token \
    "${TOKDIR}/approov_token_1_valid" \
    -genExample \
    example.com

  # 1.1 Valid Token.
  local expected_status=200
  run_test \
    "1.1 - Token check (valid token)" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_1_valid")" \
    "${BASE_URL}/token-check"

  # 1.2 Invalid Token (signature/type invalid).
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

 if [[ -f "${TOKDIR}/approov_token_1_invalid" ]]; then
  run_test \
    "1.2 - Token check (invalid token)" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_1_invalid")" \
    "${BASE_URL}/token-check"
    else
    skip_test \
      "1.2 - Token check (invalid token)" \
      "approov_token_1_invalid missing"
  fi

  # 2) Token Binding ["Authorization"].
  local AUTH_VAL="ExampleAuthToken=="
  export HASH_INPUT="${AUTH_VAL}"

  # 2.0 Generate valid binding token.
  gen_token \
    "${TOKDIR}/approov_token_2_valid" \
    -setDataHashInToken "${HASH_INPUT}" \
    -genExample \
    example.com

  # 2.1 Valid Token + correct Authorization header.
  expected_status=200
  run_test \
    "2.1 - Single binding (valid token + header)" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_valid")" \
    "${BASE_URL}/token-binding"

  # 2.2 Missing Authorization header.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "2.2 - Single binding (missing Authorization header)" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_valid")" \
    "${BASE_URL}/token-binding"

  # 2.3 Incorrect Authorization header.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "2.3 - Single binding (incorrect Authorization header)" \
    "${expected_status}" \
    -H "Authorization: BadAuthToken==" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_valid")" \
    "${BASE_URL}/token-binding"

  # 2.4 Invalid binding token.
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

  if [[ -f "${TOKDIR}/approov_token_2_invalid" ]]; then
  run_test \
    "2.4 - Single binding (invalid token)" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_2_invalid")" \
    "${BASE_URL}/token-binding"
  else
    skip_test \
      "2.4 - Single binding (invalid token)" \
      "approov_token_2_invalid missing"
  fi

  # 3) Token Binding ["Authorization", "Content-Digest"].
  local AUTH_VAL2="ExampleAuthToken=="
  local CD_VAL="ContentDigest=="
  export HASH_INPUT="${AUTH_VAL2}${CD_VAL}"

  # 3.0 Generate valid double-binding token.
  gen_token \
    "${TOKDIR}/approov_token_3_valid" \
    -setDataHashInToken "${HASH_INPUT}" \
    -genExample \
    example.com

  # 3.1 Valid token + both binding headers.
  expected_status=200
  run_test \
    "3.1 - Double binding (valid token + headers)" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL2}" \
    -H "Content-Digest: ${CD_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_valid")" \
    "${BASE_URL}/token-double-binding"

  # 3.2 Missing both binding headers.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "3.2 - Double binding (missing binding headers)" \
    "${expected_status}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_valid")" \
    "${BASE_URL}/token-double-binding"

  # 3.3 Incorrect binding headers.
  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi
  run_test \
    "3.3 - Double binding (incorrect binding headers)" \
    "${expected_status}" \
    -H "Authorization: BadAuthToken==" \
    -H "Content-Digest: BadContentDigest==" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_valid")" \
    "${BASE_URL}/token-double-binding"

  # 3.4 Invalid token.
  if gen_token \
    "${TOKDIR}/approov_token_3_invalid" \
    -setDataHashInToken "${HASH_INPUT}" \
    -genExample \
    example.com \
    -type invalid; then
    :
  else
    err "Failed to generate approov_token_3_invalid (continuing tests)"
  fi

  if [[ "${is_approov_disabled}" == true ]]; then
    expected_status=200
  else
    expected_status=401
  fi

  if [[ -f "${TOKDIR}/approov_token_3_invalid" ]]; then
  run_test \
    "3.4 - Double binding (invalid token)" \
    "${expected_status}" \
    -H "Authorization: ${AUTH_VAL2}" \
    -H "Content-Digest: ${CD_VAL}" \
    -H "approov-token: $(cat "${TOKDIR}/approov_token_3_invalid")" \
    "${BASE_URL}/token-double-binding"
  else
    skip_test \
      "3.4 - Double binding (invalid token)" \
      "approov_token_3_invalid missing"
  fi

  # 4) Extreme tests: headers and tokens presence/absence.
  # 4.1 Protected endpoints without any Approov header.
  local exp_protected
  exp_protected="$(expected_protected_status "401")"

  run_test \
    "4.1 - token-check (no Approov header)" \
    "${exp_protected}" \
    "${BASE_URL}/token-check"

  run_test \
    "4.1 - token-binding (no Approov header)" \
    "${exp_protected}" \
    "${BASE_URL}/token-binding"

  run_test \
    "4.1 - token-double-binding (no Approov header)" \
    "${exp_protected}" \
    "${BASE_URL}/token-double-binding"

  # 4.2 Valid token only (no binding headers).
  if [[ -f "${TOKDIR}/approov_token_1_valid" ]]; then
    run_test \
      "4.2 - unprotected (valid token only)" \
      "200" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_1_valid")" \
      "${BASE_URL}/unprotected"

    run_test \
      "4.2 - token-check (valid token only)" \
      "200" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_1_valid")" \
      "${BASE_URL}/token-check"

    run_test \
      "4.2 - token-binding (valid token only)" \
      "${exp_protected}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_1_valid")" \
      "${BASE_URL}/token-binding"

    run_test \
      "4.2 - token-double-binding (valid token only)" \
      "${exp_protected}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_1_valid")" \
      "${BASE_URL}/token-double-binding"
  else
    skip_test \
      "4.2 - valid token only (various endpoints)" \
      "approov_token_1_valid missing"
  fi

  # 4.3 Valid single-binding token + Authorization header.
  if [[ -f "${TOKDIR}/approov_token_2_valid" ]]; then
    run_test \
      "4.3 - token-binding (valid token + Authorization)" \
      "200" \
      -H "Authorization: ${AUTH_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_2_valid")" \
      "${BASE_URL}/token-binding"

    run_test \
      "4.3 - unprotected (valid token + Authorization)" \
      "200" \
      -H "Authorization: ${AUTH_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_2_valid")" \
      "${BASE_URL}/unprotected"

    run_test \
      "4.3 - token-check (valid token + Authorization)" \
      "200" \
      -H "Authorization: ${AUTH_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_2_valid")" \
      "${BASE_URL}/token-check"

    run_test \
      "4.3 - token-double-binding (valid token + Authorization)" \
      "${exp_protected}" \
      -H "Authorization: ${AUTH_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_2_valid")" \
      "${BASE_URL}/token-double-binding"
  else
    skip_test \
      "4.3 - binding-1/unprotected/token-check/token-double-binding" \
      "approov_token_2_valid missing"
  fi

  # 4.4 Valid double-binding token + two binding headers.
  if [[ -f "${TOKDIR}/approov_token_3_valid" ]]; then
    run_test \
      "4.4 - token-double-binding (valid token + two bindings)" \
      "200" \
      -H "Authorization: ${AUTH_VAL2}" \
      -H "Content-Digest: ${CD_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_3_valid")" \
      "${BASE_URL}/token-double-binding"

    run_test \
      "4.4 - unprotected (valid token + two bindings)" \
      "200" \
      -H "Authorization: ${AUTH_VAL2}" \
      -H "Content-Digest: ${CD_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_3_valid")" \
      "${BASE_URL}/unprotected"

    run_test \
      "4.4 - token-check (valid token + two bindings)" \
      "200" \
      -H "Authorization: ${AUTH_VAL2}" \
      -H "Content-Digest: ${CD_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_3_valid")" \
      "${BASE_URL}/token-check"

    run_test \
      "4.4 - token-binding (valid token + two bindings)" \
      "${exp_protected}" \
      -H "Authorization: ${AUTH_VAL2}" \
      -H "Content-Digest: ${CD_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_3_valid")" \
      "${BASE_URL}/token-binding"
  else
    skip_test \
      "4.4 - double-binding scenarios (approov_token_3_valid)" \
      "token file missing"
  fi

  # 5) Extreme tests: bad tokens and binding mismatches.
  # 5.1 Bad token with bad signature (modified third segment).
  if [[ -f "${TOKDIR}/approov_token_1_valid" ]]; then
    local good_tok
    local bad_sig_tok

    good_tok="$(<"${TOKDIR}/approov_token_1_valid")"
    bad_sig_tok="$(
      awk -F. \
        '{printf "%s.%s.%s", $1, $2, "bogussignature"}' \
        <<<"${good_tok}"
    )"

    run_test \
      "5.1 - Bad token (bad signature)" \
      "$(expected_protected_status "401")" \
      -H "approov-token: ${bad_sig_tok}" \
      "${BASE_URL}/token-check"
  else
    skip_test \
      "5.1 - Bad token (bad signature)" \
      "approov_token_1_valid missing"
  fi

  # 5.2 Bad token with invalid encoding.
  local bad_token_invalid_encoding
  bad_token_invalid_encoding="eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0."\
"eyJleHAiOjE5OTk5OTk5OTksImRpZCI6IkV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSJ9."\
"NwqfsaOUBfXaf8KxRZovYCy0c6hqy29g88z1LIgzuQY"

  run_test \
    "5.2 - Bad token (invalid encoding)" \
    "$(expected_protected_status "401")" \
    -H "approov-token: ${bad_token_invalid_encoding}" \
    "${BASE_URL}/token-check"

  # 5.3 / 5.4 Bad token with no expiry (real or simulated).
  local exp_noexp
  exp_noexp="$(expected_protected_status "401")"

  if [[ -n "${BAD_TOKEN_NO_EXPIRY:-}" ]]; then
    run_test \
      "5.3 - Bad token (no expiry)" \
      "${exp_noexp}" \
      -H "approov-token: ${BAD_TOKEN_NO_EXPIRY}" \
      "${BASE_URL}/token-check"
  elif [[ -f "${TOKDIR}/approov_token_1_valid" ]]; then
    local hdr_payload
    local noexp_tok

    hdr_payload="$(cut -d. -f1-2 <"${TOKDIR}/approov_token_1_valid")"
    noexp_tok="${hdr_payload}.nosig"

    run_test \
      "5.4 - Bad token (no expiry simulated)" \
      "${exp_noexp}" \
      -H "approov-token: ${noexp_tok}" \
      "${BASE_URL}/token-check"
  else
    skip_test \
      "5.3/5.4 - Bad token (no expiry)" \
      "no BAD_TOKEN_NO_EXPIRY and approov_token_1_valid missing"
  fi

  # 5.5 Explicit expired token.
  local bad_token_expired
  bad_token_expired="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."\
"eyJhdWQiOiIiLCJleHAiOjE3NjIzNTg3OTcsImlwIjoiMS4yLjMuNCIsImRpZCI6IkV4YW1w"\
"bGVBcHByb292VG9rZW5ESUQ9PSJ9.vQZqzUAOkjdqDRWMjUYQFwkwFd9sRn1UjXyZCIymNcE"

  run_test \
    "5.5 - Bad token (expired)" \
    "$(expected_protected_status "401")" \
    -H "approov-token: ${bad_token_expired}" \
    "${BASE_URL}/token-check"

  # 5.6 Missing binding but valid full token for double-binding endpoint.
  if [[ -f "${TOKDIR}/approov_token_1_valid" ]]; then
    run_test \
      "5.6 - Missing binding with good full token" \
      "$(expected_protected_status "401")" \
      -H "Authorization: ${AUTH_VAL}" \
      -H "Content-Digest: ${CD_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_1_valid")" \
      "${BASE_URL}/token-double-binding"
  else
    skip_test \
      "5.6 - Missing binding with good full token" \
      "approov_token_1_valid missing"
  fi

  # 5.7 / 5.8 / 5.9 Various binding issues with double-binding token.
  if [[ -f "${TOKDIR}/approov_token_3_valid" ]]; then
    # 5.7 Missing Authorization with valid binding token.
    run_test \
      "5.7 - Missing Authorization with valid binding token" \
      "$(expected_protected_status "401")" \
      -H "Content-Digest: ${CD_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_3_valid")" \
      "${BASE_URL}/token-double-binding"

    # 5.8 Good full token with binding.
    run_test \
      "5.8 - Good full token with correct binding" \
      "200" \
      -H "Authorization: ${AUTH_VAL}" \
      -H "Content-Digest: ${CD_VAL}" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_3_valid")" \
      "${BASE_URL}/token-double-binding"

    # 5.9 Correctly signed token but wrong binding headers.
    run_test \
      "5.9 - Correct token but wrong binding headers" \
      "$(expected_protected_status "401")" \
      -H "Authorization: WrongAuth==" \
      -H "Content-Digest: WrongDigest==" \
      -H "approov-token: $(<"${TOKDIR}/approov_token_3_valid")" \
      "${BASE_URL}/token-double-binding"
  else
    skip_test \
      "5.7/5.8/5.9 - Binding issues with binding-2 token" \
      "approov_token_3_valid missing"
  fi

  echo
  echo "Full request and response details are saved in:"
  echo "  ${LOGFILE}"
}

main "$@"
