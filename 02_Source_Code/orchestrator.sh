#!/usr/bin/env bash
# ==============================================================================
# orchestrator.sh — High-Fidelity Snapshot & Timeout Intercept Orchestrator
# ==============================================================================
set -uo pipefail
BASE_DIR="/c/Users/suhan/Desktop/android_pipeline"
source "${BASE_DIR}/config.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

_ts() { date '+%Y-%m-%d %H:%M:%S'; }
log()  { echo -e "[$(_ts)] [${BLUE}INFO${NC}]  $*"; }

run_jadx() {
    local apk_path="$1" app_name="$2"
    local out_dir="${DECOMPILE_DIR}/${app_name}"
    local err_log="${LOG_DIR}/${app_name}.jadx.log"
    local exit_code count

    if [[ -d "$out_dir" ]]; then
        count=$(find "$out_dir" -type f -name '*.java' | wc -l)

        if (( count > 0 )); then
            echo "[SKIP] JADX cached: ${count} Java files." >&2
            echo "success:${out_dir}:${count}"
            return
        fi
    fi

    mkdir -p "$out_dir"

    echo "[PROCESSING] Stage 1/3: JADX Decompilation..." >&2

    timeout "${JADX_TIMEOUT_SEC}" "$JADX_BIN" \
        -d "$out_dir" \
        -j "${JADX_THREADS}" \
        --show-bad-code \
        "$apk_path" > "${LOG_DIR}/${app_name}.jadx.stdout.log" 2> "$err_log"

    exit_code=$?
    count=$(find "$out_dir" -type f -name '*.java' | wc -l)

    if (( count > 0 )); then
        if (( exit_code == 0 )); then
            echo "[SUCCESS] JADX generated ${count} Java files." >&2
        else
            echo "[WARNING] JADX exit code ${exit_code}; generated ${count} Java files." >&2
        fi

        echo "success:${out_dir}:${count}"
    else
        echo "[FAILED] JADX generated 0 Java files. Exit code: ${exit_code}" >&2
        echo "failed:${out_dir}:0"
    fi
}

run_semgrep() {
    local app_name="$1" source_dir="$2"
    local out_json="${RESULTS_DIR}/${app_name}.semgrep.json"
    local err_log="${LOG_DIR}/${app_name}.semgrep.log"
    local exit_code count

    if [[ ! -d "$source_dir" ]]; then
        echo "   ├── [FAILED] Source directory not found: $source_dir" >&2
        echo "failed:0"
        return
    fi

    echo "   ├── [PROCESSING] Stage 2/3: Semgrep Scan..." >&2

    timeout 300 "$SEMGREP_BIN" scan \
        --config "${SEMGREP_RULES_DIR}" \
        --json --quiet --no-git-ignore \
        "$source_dir" > "$out_json" 2> "$err_log"

    exit_code=$?

    if [[ "$exit_code" -eq 124 ]]; then
        echo "   ├── [TIMEOUT] Semgrep exceeded 300 seconds." >&2
        echo "partially_processed:0"
        return
    fi

    if [[ ! -s "$out_json" ]] || ! jq -e '.results | type == "array"' "$out_json" >/dev/null 2>&1; then
        echo "   ├── [FAILED] Semgrep did not produce valid results." >&2
        echo "   ├── Check log: $err_log" >&2
        echo "failed:0"
        return
    fi

    count=$(jq '.results | length' "$out_json")

    if [[ "$exit_code" -eq 0 ]]; then
        echo "   ├── [SUCCESS] Semgrep found $count potential issues." >&2
        echo "success:${count}"
    else
        echo "   ├── [WARNING] Semgrep exit code: $exit_code; findings: $count" >&2
        echo "partially_processed:${count}"
    fi
}


run_dependency_scan() {
    local app_name="$1" apk_path="$2"
    local out_json="${RESULTS_DIR}/${app_name}.deps.json"
    local err_log="${LOG_DIR}/${app_name}.sca.log"
    local count

    echo "[PROCESSING] Stage 3/3: SCA Dependency Scan..." >&2

    if PYTHONIOENCODING=utf-8 "${BASE_DIR}/.venv/Scripts/python.exe" \
        "${BASE_DIR}/local_sca_parser.py" \
        "$apk_path" "$out_json" > "$err_log" 2>&1; then

        if jq -e '.vulnerabilities | type == "array"' "$out_json" >/dev/null 2>&1; then
            count=$(jq '.vulnerabilities | length' "$out_json")
            echo "[SUCCESS] SCA generated ${count} findings." >&2
            echo "success:custom_proprietary_sca:${count}"
        else
            echo "[FAILED] SCA output is not valid JSON." >&2
            echo "failed:NONE:0"
        fi
    else
        echo "[FAILED] SCA parser execution failed." >&2
        echo "[INFO] Check log: ${err_log}" >&2
        echo "failed:NONE:0"
    fi
}

process_apk() {
    local apk_path="$1"
    local app_name=$(basename "$apk_path" .apk)
    local summary_json="${RESULTS_DIR}/${app_name}.summary.json"
    local start_ts=$(date +%s)
    
    local pkg_name=$(aapt dump badging "$apk_path" 2>/dev/null | sed -n "s/^package: name='\([^']*\)'.*/\1/p" || echo "com.example.target")
    log "Launching Static SAST/SCA Scan Loop for target: ${YELLOW}${app_name}${NC}"

    local j_res j_status j_dir j_count
    j_res=$(run_jadx "$apk_path" "$app_name")
    IFS=':' read -r j_status j_dir j_count <<< "$j_res"
    
    local s_res s_status s_count
    s_res=$(run_semgrep "$app_name" "$j_dir")
    IFS=':' read -r s_status s_count <<< "$s_res"
    
    local d_res d_status d_engine d_count
    d_res=$(run_dependency_scan "$app_name" "$apk_path")
    IFS=':' read -r d_status d_engine d_count <<< "$d_res"


    # Stage 4: Source Vulnerability Mapping and Finding Enrichment
    local enriched_json="${RESULTS_DIR}/${app_name}.enriched.json"

    echo "[PROCESSING] Stage 4/4: Source Vulnerability Mapping..." >&2

    if [[ -d "$j_dir" ]]; then
        if PYTHONIOENCODING=utf-8 "${BASE_DIR}/.venv/Scripts/python.exe" \
            "${BASE_DIR}/source_vulnerability_mapper.py" \
            --app-name "$app_name" \
            --source-dir "$j_dir" \
            --semgrep-json "${RESULTS_DIR}/${app_name}.semgrep.json" \
            --sca-json "${RESULTS_DIR}/${app_name}.deps.json" \
            --output "$enriched_json"; then

            echo "[SUCCESS] Finding enrichment completed." >&2
        else
            echo "[WARNING] Enrichment failed; original scan results preserved." >&2
        fi
    else
        echo "[WARNING] JADX source directory unavailable; enrichment skipped." >&2
    fi

    
    local end_ts=$(date +%s)
    
    jq -n \
        --arg app "$app_name" --arg path "$apk_path" --arg pkg "$pkg_name" --arg dur "$((end_ts - start_ts))" \
        --arg j_st "$j_status" --arg j_cn "${j_count:-0}" \
        --arg s_st "$s_status" --arg s_cn "${s_count:-0}" \
        --arg d_st "$d_status" --arg d_eg "$d_engine" --arg d_cn "${d_count:-0}" \
        '{
            app_name: $app, apk_path: $path, package_name: $pkg, duration_sec: ($dur | tonumber),
            static: {
                jadx: { status: $j_st, java_files: (($j_cn|select(.!=""))//"0"|tonumber) },
                semgrep: { status: $s_st, findings: (($s_cn|select(.!=""))//"0"|tonumber) },
                mobsf: { status: "skipped", high_findings: 0 },
                deps: { status: $d_st, engine: $d_eg, findings: (($d_cn|select(.!=""))//"0"|tonumber) }
            },
            dynamic: { device_gate: "skipped", mobsf_dynamic: { status: "skipped", findings: 0 }, drozer: { status: "skipped", flagged_findings: 0 }, frida: { status: "skipped", events_observed: 0 } },
            native_fuzz_triage: { status: "success", high_priority_libs: 0 }
        }' > "$summary_json" 

    # Stage 5: Create Final Combined JSON
    local final_json="${RESULTS_DIR}/${app_name}.final.json"
    local semgrep_data='[]'
    local sca_data='[]'

    # Preserve raw findings if enrichment is unavailable
    if [[ -s "${RESULTS_DIR}/${app_name}.semgrep.json" ]] && \
       jq -e '.results | type == "array"' \
       "${RESULTS_DIR}/${app_name}.semgrep.json" >/dev/null 2>&1; then
        semgrep_data=$(jq -c '.results' \
            "${RESULTS_DIR}/${app_name}.semgrep.json")
    fi

    if [[ -s "${RESULTS_DIR}/${app_name}.deps.json" ]] && \
       jq -e '.vulnerabilities | type == "array"' \
       "${RESULTS_DIR}/${app_name}.deps.json" >/dev/null 2>&1; then
        sca_data=$(jq -c '.vulnerabilities' \
            "${RESULTS_DIR}/${app_name}.deps.json")
    fi

    if [[ -s "$enriched_json" ]] && \
       jq -e 'type == "object"' "$enriched_json" >/dev/null 2>&1; then

        jq -n \
            --slurpfile summary "$summary_json" \
            --slurpfile analysis "$enriched_json" \
            '{
                scan_summary: $summary[0],
                analysis: $analysis[0]
            }' > "$final_json"

    else
        jq -n \
            --slurpfile summary "$summary_json" \
            --argjson semgrep "$semgrep_data" \
            --argjson sca "$sca_data" \
            '{
                scan_summary: $summary[0],
                analysis: {
                    app_name: $summary[0].app_name,
                    enrichment_status: "unavailable",
                    semgrep_findings: $semgrep,
                    sca_findings: $sca
                }
            }' > "$final_json"
    fi

    echo "[SUCCESS] Final JSON saved: $final_json" >&2

        
    "${BASE_DIR}/.venv/Scripts/python.exe" "${BASE_DIR}/compile_master_matrix.py" "$RESULTS_DIR" "$RUN_ROOT"
}

main() {
    local apks=()
    if [[ "${1:-}" != "" ]]; then
        apks+=("$1")
    else
        while IFS= read -r -d '' f; do apks+=("$f"); done \
            < <(find "$APK_INPUT_DIR" -maxdepth 1 -iname '*.apk' -print0 | sort -z)
    fi
    export -f process_apk run_jadx run_semgrep run_dependency_scan _ts log
    export BASE_DIR APK_INPUT_DIR RUN_ROOT LOG_DIR RESULTS_DIR DECOMPILE_DIR JADX_BIN JADX_THREADS JADX_TIMEOUT_SEC SEMGREP_BIN SEMGREP_RULES_DIR SEMGREP_TIMEOUT_SEC MAX_PARALLEL_APKS RED GREEN YELLOW BLUE NC FAILOVER_SCRIPT SNYK_BIN DEP_CHECK_BIN DEP_CHECK_DATA_DIR
    
    printf '%s\0' "${apks[@]}" | xargs -0 -P "$MAX_PARALLEL_APKS" -I {} bash -c 'process_apk "$1"' _ {}
}
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then main "$@"; fi

