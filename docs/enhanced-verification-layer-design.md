# Architectural Blueprint: Enhanced Verification Layer

## Phase 1: Architectural Blueprint (The Integration)
* **Layered Detection Flow:**
  The sequence must be: **(1) Regex Check -> (2) Pattern Check (SSN) -> (3) NER Check**.
  *Justification:* Deterministic checks (Regex and Pattern Validation) are O(N) and highly performant. By executing them first, we can leverage the existing `createZeroMaskedBuffer` logic to mask these sensitive segments *before* the text reaches the ML-based NER model. This serves two purposes: it prevents the expensive ML model from wasting compute trying to classify already-identified structured data, and it prevents false positives where the NER might incorrectly classify parts of an SSN as an organization or location. Pattern matches are deterministic and should always take precedence.
* **Data Structure Refactor:**
  The `ScanResultPayload` returned from the Worker (in `WorkerMessage/HostMessage`) must be expanded to include a new `VerificationReport` array.
  ```typescript
  export interface VerificationReport {
    ruleId: string; // e.g., 'swedish-ssn-check'
    status: 'DETECTED' | 'NOT_DETECTED' | 'INVALID_FORMAT';
    matchesCount: number;
    executionTimeMs: number;
    message: string;
  }
  ```
  The `ScanResultPayload` will include: `jobId`, `entities: RedactionEntity[]`, `verificationReports: VerificationReport[]`, `buffer?: Int32Array` (for zero-copy transfer), `runtimeDevice`, and `durationMs`.
* **Optimization Strategy:**
  1. **Pre-compiled Strict Regexes:** Define the SSN patterns globally using `new RegExp(..., 'g')` to avoid runtime compilation overhead on every keystroke.
  2. **Two-Stage Validation (Fast-pathing):** Use a lightweight, highly restrictive regex to find candidates (e.g., `\b\d{6}[-+]?\d{4}\b` for Swedish SSNs), and only execute the computationally heavier mathematical checksum validation (like Luhn) on those matched string slices. This prevents catastrophic backtracking (ReDoS) and wasted CPU cycles.

## Phase 2: Implementation Strategy (The How)
* **Regex Implementation Detail:**
  In `src/lib/redactor/Engine.ts`, expand the `REGEX_RULES` array to include the new SSN definitions.
  ```typescript
  {
    type: 'SSN',
    rule: /\b\d{6}[-+]?\d{4}\b/g, // Specific Swedish SSN format
    validate: isSwedishSSNValid // A dedicated function running the checksum algorithm
  }
  ```
  This cleanly integrates into the existing `RegexEngine.scan` loop, which already supports custom validation functions (like `isValidLuhn` for credit cards).
* **UI Reporting Mockup:**
  Introduce a **"Verification Status Panel"** below the Svelte `RedactorEditor.svelte` transparent textarea.
  Using Svelte 5 `$derived` state, this panel will render pills/badges based on the `verificationReports` from the worker.
  - Examples: `✅ SSN Pattern Checked - 0 Found` (Subtle green), `❌ SSN Pattern Detected - 2 Masked` (High contrast amber/red).
  - Hovering over a report badge could trigger a state change that highlights the specific `RedactionEntity` spans in the twin-layer syntax overlay, providing clear visual causality to the user.

## Phase 3: Constraints & Mitigation (The Risk)
* **Latency Constraint Mitigation:**
  *Risk:* Complex regex checks or massive checksum loops blocking the Web Worker thread, delaying the return of the `ScanResultPayload` and causing the UI to feel unresponsive.
  *Mitigation:* Implement a time-budgeted execution loop similar to the existing `CustomRuleEngine`. Track `performance.now()` before the check loop; if execution exceeds a tight budget (e.g., > 5ms per check), forcefully bail out of the remaining pattern checks. This ensures deterministic bounded latency. Additionally, rely on the `Int32Array` compact numeric buffer for transferring entity boundaries back to the main thread to avoid string serialization overhead.
* **User Expectation Management:**
  The "Not a Guarantee" disclaimer should be presented contextually at the point of highest risk: data exfiltration.
  While a small, persistent footer (`"Auto-redaction is an assistive tool."`) is good, the primary mitigation should tie into the existing `verifyBeforeCopy()` function. When the user clicks the "Copy to Clipboard" button, the app should display a Svelte Toast or Snackbar stating: *"Data copied to clipboard. Disclaimer: Automated verification is not a guarantee against all PII leaks. Please review manually."* This maximizes visibility without cluttering the editing experience.
