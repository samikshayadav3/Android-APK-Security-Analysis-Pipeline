# Android-APK-Security-Analysis-Pipeline
## 1. Project Overview

This project is a static security-analysis pipeline for Android APK
files. It decompiles an APK into Java source files, scans the decompiled
source with Semgrep, performs dependency analysis through a custom SCA
parser, enriches findings with source-code evidence, and combines the
results into JSON reports.

The pipeline is designed for Android APKs generally; it is not limited
to the PPSSPP application.

## 2. Objectives

-   Decompile an Android APK and obtain its available Java source files.
-   Identify potential source-code security issues using Semgrep.
-   Identify dependency-related vulnerabilities using the project's
    custom SCA parser.
-   Map Semgrep findings to relevant source files and, where possible,
    Java classes and methods.
-   Add evidence, source locations, security explanations, and
    remediation suggestions to findings.
-   Produce structured JSON output for review and reporting.

## 3. Pipeline Workflow

The current `orchestrator.sh` runs these stages:

1.  **JADX decompilation** --- decompiles the APK and stores the output
    in the configured decompilation directory. Existing decompilation
    output is reused when Java files are already present.
2.  **Semgrep source scan** --- scans the decompiled source using the
    rules configured through `SEMGREP_RULES_DIR` and writes
    `<app_name>.semgrep.json`.
3.  **Dependency / SCA scan** --- runs `local_sca_parser.py` against the
    APK and writes `<app_name>.deps.json`.
4.  **Source vulnerability mapping and enrichment** --- runs
    `source_vulnerability_mapper.py`, enriches Semgrep findings with
    source snippets and mapping information, attempts to map Manifest
    components to Java classes, and adds remediation guidance where
    available. Output: `<app_name>.enriched.json`.
5.  **Final JSON creation** --- combines the scan summary and analysis
    into `<app_name>.final.json`. If enrichment is unavailable, raw
    Semgrep and SCA findings are preserved in the final report.
6.  **Master matrix compilation** --- runs `compile_master_matrix.py` on
    the results and run directories.

## 4. Main Project Files

  -----------------------------------------------------------------------
  File                                Purpose
  ----------------------------------- -----------------------------------
  `orchestrator.sh`                   Coordinates the analysis stages and
                                      creates the final report.

  `source_vulnerability_mapper.py`    Maps and enriches Semgrep findings
                                      with source evidence and adds SCA
                                      metadata.

  `local_sca_parser.py`               Performs the project's custom
                                      dependency/SCA analysis.

  `compile_master_matrix.py`          Compiles results into a master
                                      matrix.

  `config.env`                        Supplies paths and configuration
                                      variables used by the orchestrator.

  Semgrep rules directory             Contains the rules used for
                                      source-code scanning.
  -----------------------------------------------------------------------

## 5. Tools and Requirements

The current scripts expect these tools or project components:

-   JADX
-   Semgrep
-   Python and the configured Python virtual environment
-   `jq`
-   Android `aapt`
-   Bash environment
-   `local_sca_parser.py`
-   `compile_master_matrix.py`
-   A configured Semgrep rules directory

The orchestrator reads settings from `config.env`. Paths for the project
base directory, tool executables, APK input directory, output
directories, and parallel-run settings must be configured for the
machine running the project.

**Environment note:** The uploaded orchestrator contains a
machine-specific `BASE_DIR` and invokes the Windows virtual-environment
interpreter at `.venv/Scripts/python.exe`. Update these paths if the
project is moved to another computer or operating environment.

## 6. Running the Pipeline

From the project directory:

``` bash
bash orchestrator.sh
```

This processes APK files found in the configured APK input directory.

To process one APK explicitly:

``` bash
bash orchestrator.sh path/to/application.apk
```

Before running, confirm that `config.env` exists, configured tool paths
are valid, the Python environment has the required packages, the SCA
parser and matrix compiler are present, the Semgrep rules directory
exists, and the APK is available at the supplied path or configured
input directory.

## 7. Output Files

For an APK named `example.apk`, the orchestrator uses `example` as the
application name and creates these principal files in the configured
results directory:

  -----------------------------------------------------------------------
  Output                              Description
  ----------------------------------- -----------------------------------
  `example.semgrep.json`              Raw Semgrep scan results.

  `example.deps.json`                 Raw dependency/SCA results.

  `example.enriched.json`             Enriched findings with source
                                      mapping and evidence.

  `example.summary.json`              High-level scan status and finding
                                      counts.

  `example.final.json`                Combined report containing
                                      `scan_summary` and `analysis`.
  -----------------------------------------------------------------------

Exact output locations are controlled by `config.env`.

## 8. Understanding the Final JSON

The final report has two main top-level sections.

### `scan_summary`

Contains the APK name and path, package name, elapsed time, and
high-level status/count information for pipeline stages.

The current orchestrator records some additional stages as `skipped`,
including MobSF, device-based dynamic analysis, Drozer, and Frida. A
skipped stage has not performed an analysis; its zero finding count must
not be interpreted as proof that the APK is safe.

### `analysis`

When enrichment succeeds, this section contains mapper output such as:

-   `app_name`
-   `source_directory`
-   `module` and `module_version`
-   `summary`
-   `semgrep_findings`
-   `sca_findings`

For Semgrep findings, `source_mapping` may include the source file,
relative path, class name, component, method name, line range, code
evidence, Manifest evidence, related Java source, mapping method, and
validation status.

For SCA findings, the mapper labels the source mapping as
`dependency_metadata` and the validation status as
`Dependency Evidence Only`. Dependency findings do not necessarily map
to a Java method or source line.

## 9. Important Interpretation Notes

-   Semgrep findings are potential issues identified by configured rules
    and should be reviewed.
-   A Manifest finding, such as an exported Android component, is a
    configuration-level finding. Mapping it to a Java class does not
    automatically mean a particular Java method is vulnerable.
-   A method inventory is contextual information about methods in a
    related class; a method appearing in that inventory is not thereby
    vulnerable.
-   `Needs Review` means the finding requires human validation. It does
    not confirm exploitability.
-   SCA findings concern dependency/component vulnerability evidence and
    may not have Java source locations.
-   Successful tool execution does not mean the APK is free of
    vulnerabilities.
-   Results depend on the configured Semgrep rules, available decompiled
    source, SCA parser data, and tool versions.

## 10. Current Scope and Limitations

-   The active pipeline performs JADX decompilation, Semgrep scanning,
    custom SCA parsing, source finding enrichment, final JSON
    generation, and master matrix compilation.
-   The orchestrator currently records MobSF and the listed
    dynamic-analysis stages as skipped.
-   The source mapper enriches findings produced by scanners; it does
    not independently prove exploitability.
-   Java method-level vulnerability discovery depends on the Semgrep
    rules and other scanners. The mapper's method mapping is based on
    detected findings and source structure; it is not a complete Java
    parser or a standalone vulnerability detector.

## 11. Suggested Review Process

1.  Open the final JSON report for the APK.
2.  Review `scan_summary` to see which stages actually ran.
3.  Review each Semgrep finding, including rule ID, severity, source
    location, and evidence.
4.  Review each SCA finding and identify the affected
    dependency/component.
5.  Treat `Needs Review` findings as items requiring manual validation.
6.  Do not treat skipped analysis stages or empty finding lists as proof
    of safety.

------------------------------------------------------------------------

**Project note:** This README describes the workflow visible in the
current `orchestrator.sh` and `source_vulnerability_mapper.py`.
Configuration values, exact tool versions, installation commands, and
the detailed SCA detection methodology should be added after checking
the corresponding project files and environment.
