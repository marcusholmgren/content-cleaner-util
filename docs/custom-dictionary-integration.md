## Custom PII Dictionary & Rule Builder Integration

**Goal:** Design the architecture, UI implementation, and technical integration strategy for a user-configurable custom redaction dictionary that extends the application's existing Hybrid Detection Engine (Regex + On-Device NER).

### Phase 1: Architectural Blueprint (The Integration)

**Data Structures (Preliminary):**

```typescript
export type CustomRuleType = 'EXACT' | 'PHRASE' | 'REGEX';

export interface CustomRule {
	id: string;
	type: CustomRuleType;
	value: string;
	caseSensitive: boolean;
	enabled: boolean;
	createdAt: number;
}

export interface CompiledCustomRule {
	id: string;
	type: CustomRuleType;
	matcher: string | RegExp;
}

export interface SyncCustomRulesPayload {
	type: 'SYNC_CUSTOM_RULES';
	rules: CustomRule[];
}
```

**Data Flow Diagram:**

```text
[ Svelte 5 UI (Main Thread) ]
        |
        | 1. User adds/toggles rule in UI (bound to $state)
        v
[ Client Storage Layer ] ---> Persisted to IndexedDB (localforage/idb-keyval)
        |
        | 2. Rules serialized & sent via postMessage on change
        v
[ Web Worker Sandbox ]
        |
        | 3. Worker receives SYNC_CUSTOM_RULES
        v
[ Compilation Engine ] ---> Compiles regex, builds Aho-Corasick Trie for exact/phrases
        |
        | 4. Incoming text scanned via hybrid pipeline
        v
[ Execution Pipeline ]
    a. Built-in Hard Regex (Emails, IPs, etc.)
    b. Custom Rules (Aho-Corasick + SafeRegex)
    c. Probabilistic NER (WASM/WebGPU)
        |
        v
[ Result Aggregator ] ---> Resolves overlaps -> postMessage SCAN_SUCCESS
```

**Precedence & Collision Hierarchy:**

1.  **Built-in Hard Regex:** Highest priority. Patterns like valid Credit Cards or specific high-entropy tokens are strictly defined and have minimal false positives. They act as immutable ground truth.
2.  **User Custom Rules:** Second priority. User-defined rules override general AI detections, ensuring that user intent (e.g., masking an internal codename) is always respected over AI uncertainty or false negatives.
3.  **Probabilistic NER:** Lowest priority. Acts as a catch-all for generalized PII (PER, ORG, LOC).

_Justification:_ If a lower-priority match overlaps with a higher-priority match (e.g., NER tags a phrase that a Custom Rule also matches), the engine resolves this by deferring to the higher-priority rule, which dictates the redaction boundary and metadata (`source: 'CUSTOM'`).

**Matching Algorithm & Data Structure Choice:**

- **Exact & Phrase Matches:** **Aho-Corasick Automaton**. It processes the target text in a single pass with a time complexity of $O(N + M + Z)$ where $N$ is text length, $M$ is total pattern length, and $Z$ is the number of matches. This easily satisfies the $< 10\,\text{ms}$ latency constraint even with a dictionary of 5,000+ words.
- **Custom RegEx Matches:** **Pre-compiled `RegExp` array**. Because custom regex cannot easily be trie-optimized, they are executed sequentially, guarded by time limits and ReDoS checks.

### Phase 2: Implementation Strategy (The How)

**Persistence Layer & Schema:**

- **Storage Choice:** **IndexedDB** (via a lightweight wrapper like `idb-keyval`).
- **Why:** `localStorage` is synchronous and blocks the main thread, causing UI jank when dealing with large datasets. IndexedDB provides asynchronous, non-blocking transactional reads/writes perfectly suited for client-side persistence.
- **Initialization:** On app startup, the Svelte store fetches the `custom_rules` object store from IndexedDB, populates the UI `$state`, and dispatches the initial `SYNC_CUSTOM_RULES` payload to the worker before the first keystroke.

**Worker Sync & State API:**

```typescript
import { get, set } from 'idb-keyval';
import type { CustomRule } from './types';
import type { WorkerManager } from './WorkerManager';

export class CustomRuleStore {
	rules = $state<CustomRule[]>([]);
	private workerManager: WorkerManager;

	constructor(workerManager: WorkerManager) {
		this.workerManager = workerManager;
	}

	async loadCustomRules() {
		this.rules = (await get('customRules')) || [];
		this.syncToWorker();
	}

	async addCustomRule(rule: Omit<CustomRule, 'id' | 'createdAt'>) {
		const newRule = { ...rule, id: crypto.randomUUID(), createdAt: Date.now() };
		this.rules.push(newRule);
		await set('customRules', $state.snapshot(this.rules));
		this.syncToWorker();
	}

	async removeCustomRule(id: string) {
		this.rules = this.rules.filter((r) => r.id !== id);
		await set('customRules', $state.snapshot(this.rules));
		this.syncToWorker();
	}

	async toggleRule(id: string) {
		const idx = this.rules.findIndex((r) => r.id === id);
		if (idx > -1) {
			this.rules[idx].enabled = !this.rules[idx].enabled;
			await set('customRules', $state.snapshot(this.rules));
			this.syncToWorker();
		}
	}

	syncToWorker() {
		this.workerManager.worker?.postMessage({
			type: 'SYNC_CUSTOM_RULES',
			rules: $state.snapshot(this.rules.filter((r) => r.enabled))
		});
	}
}
```

**Worker Execution Loop:**

1.  **State Hydration:** When `SYNC_CUSTOM_RULES` is received in `redactor.worker.ts`, the worker builds the Aho-Corasick Trie (or a simplified equivalent for MVP, like a single `RegExp` alternation for exact phrases to save complexity if trie isn't available) for EXACT/PHRASE rules and parses REGEX rules. This occurs asynchronously off the hot path.
2.  **Execution:** Inside the `scanText` loop, _after_ Built-in Regex but _before_ NER inference:
    - The input string passes through the Aho-Corasick engine (or equivalent).
    - Valid custom regexes are executed (`String.prototype.matchAll()`).
3.  **Decoration & Resolution:** Matches are mapped to a `RedactionEntity` with `source: 'CUSTOM'` and a specific `type` like `CUSTOM_RULE`. The results are merged with built-in regex outputs. `ConflictResolver` handles resolving overlapping indices (prioritizing REGEX > CUSTOM > NER). The heavy NER pass skips processing spans already finalized by Custom Rules (via zero-masking).

### Phase 3: Constraints, Security & Risk Mitigation

**Top 2 Performance Bottlenecks & Solutions:**

1.  **Bottleneck: Iterating hundreds of separate `.match()` calls.**
    _Solution:_ Group EXACT/PHRASE rules into the Aho-Corasick Trie (or a single massive `RegExp` like `/(phrase1|phrase2)/g` for quick engine optimization) to guarantee a single-pass scan regardless of dictionary size.
2.  **Bottleneck: Re-compiling the Trie/Regex on every keystroke.**
    _Solution:_ The worker maintains local state (`compiledCustomRules`). Compilation _only_ happens on a `SYNC_CUSTOM_RULES` event. The scanning loop simply re-uses the pre-compiled state across all debounced keystrokes.

**Security, Validation & ReDoS Defenses:**

- **Syntax Validation (Main Thread):** The main thread runs a quick syntax validation (`new RegExp(pattern)`) inside a `try/catch` before saving a custom regex to provide immediate UI feedback on malformed syntax.
- **ReDoS Sandboxing (Worker Thread):** Arbitrary user-supplied regexes can cause catastrophic backtracking, hanging the Web Worker.
  - _Mitigation 1 (Complexity Limiter):_ Implement a Regex complexity analyzer (or simply restrict certain quantifiers) to reject patterns with heavily nested quantifiers (e.g., `(a+)+$`).
  - _Mitigation 2 (Execution Timeout):_ Wrap custom regex execution in a timed loop checking `performance.now()`. If a single user regex takes $> 5\,\text{ms}$ to evaluate, it is aborted and auto-disabled. (Note: standard JS `RegExp` doesn't have built-in timeouts, so this is hard. A safer approach for JS is to rely on the fact it's in a Web Worker—if the worker hangs, the main thread UI doesn't freeze. The main thread could implement a watchdog timer on the worker response and terminate/restart the worker if it takes > 2 seconds).

**UI/UX Specification:**

- **Rule Manager Component:** A slide-out drawer or a section below the editor containing a data table or list.
  - _Columns:_ Rule Type (Dropdown), Value (Text Input), Match Case (Toggle), Enabled (Toggle), Actions (Delete/Edit).
- **In-Editor Feedback:** When text is matched by a custom rule, the syntax-highlighted overlay will use a distinct visual affordance (e.g., a dashed purple underline instead of the solid blue/yellow used for NER/Regex) so the user immediately recognizes the trigger source.
- **Tooltip Inspector:** Hovering or clicking a redacted entity reveals a small popover showing the source: `Custom Rule Matched: "Project Titan"`.
