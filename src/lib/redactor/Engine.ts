import type {
	CustomRule,
	CustomRuleType,
	EntityType,
	RedactionEntity,
	ScanConfig,
	VerificationReport
} from './types';

export const DEFAULT_ENABLED_TYPES: EntityType[] = [
	'PER',
	'ORG',
	'LOC',
	'EMAIL',
	'TOKEN',
	'IP',
	'CREDIT_CARD',
	'SSN',
	'SUSPECTED_TOKEN',
	'AMBIGUOUS_PER',
	'AMBIGUOUS_ORG',
	'CUSTOM_RULE'
];

export const REDACTION_LABELS: Record<EntityType, string> = {
	PER: '[NAME]',
	AMBIGUOUS_PER: '[NAME]',
	ORG: '[ORG]',
	AMBIGUOUS_ORG: '[ORG]',
	LOC: '[LOC]',
	EMAIL: '[EMAIL]',
	TOKEN: '[TOKEN]',
	SUSPECTED_TOKEN: '[TOKEN]',
	IP: '[IP]',
	CREDIT_CARD: '[CREDIT_CARD]',
	SSN: '[SSN]',
	CUSTOM_RULE: '[CUSTOM]'
};

const ENTITY_TYPE_TO_ENUM: Record<EntityType, number> = {
	PER: 1,
	ORG: 2,
	LOC: 3,
	EMAIL: 4,
	TOKEN: 5,
	IP: 6,
	CREDIT_CARD: 7,
	SSN: 12,
	SUSPECTED_TOKEN: 8,
	AMBIGUOUS_PER: 9,
	AMBIGUOUS_ORG: 10,
	CUSTOM_RULE: 11
};

const ENUM_TO_ENTITY_TYPE: Record<number, EntityType> = {
	1: 'PER',
	2: 'ORG',
	3: 'LOC',
	4: 'EMAIL',
	5: 'TOKEN',
	6: 'IP',
	7: 'CREDIT_CARD',
	8: 'SUSPECTED_TOKEN',
	9: 'AMBIGUOUS_PER',
	10: 'AMBIGUOUS_ORG',
	11: 'CUSTOM_RULE',
	12: 'SSN'
};

const AMBIGUOUS_PROPER_NOUNS = new Set([
	'apple',
	'ruby',
	'amazon',
	'may',
	'april',
	'june',
	'august',
	'grace',
	'hope',
	'chase',
	'target',
	'shell',
	'oracle',
	'meta',
	'linear',
	'notion',
	'slack',
	'stripe',
	'RUST',
	'rust',
	'go',
	'swift'
]);

const WORD_CHAR_REGEX = /[\p{L}\p{N}_]/u;

/**
 * Validate custom rule value & guard against ReDoS (catastrophic backtracking) in REGEX rules.
 */
export interface RuleValidationResult {
	valid: boolean;
	error?: string;
}

// Detects nested quantifiers inside groups such as (a+)+, (.*)+, ([a-z]*)*, (a+){2,}
const REDOS_NESTED_QUANTIFIER_REGEX = /\([^()]*[+*?][^()]*\)\s*(?:[+*?]|\{\d+,\d*\})/;

export function validateCustomRule(type: CustomRuleType, value: string): RuleValidationResult {
	const trimmed = value.trim();
	if (!trimmed) {
		return { valid: false, error: 'Rule pattern or phrase cannot be empty.' };
	}

	if (trimmed.length > 500) {
		return { valid: false, error: 'Rule value cannot exceed 500 characters.' };
	}

	if (type === 'REGEX') {
		if (REDOS_NESTED_QUANTIFIER_REGEX.test(trimmed)) {
			return {
				valid: false,
				error: 'Unsafe regex: nested quantifiers risk catastrophic backtracking (ReDoS).'
			};
		}
		try {
			new RegExp(trimmed, 'g');
		} catch (err) {
			return {
				valid: false,
				error: err instanceof Error ? err.message : 'Invalid regular expression syntax.'
			};
		}
	}

	return { valid: true };
}

interface AutomatonOutput {
	id: string;
	type: CustomRuleType;
	value: string;
	length: number;
}

interface TrieNode {
	children: Map<string, number>;
	fail: number;
	outputs: AutomatonOutput[];
}

/**
 * Aho-Corasick Automaton for O(N + M + Z) single-pass matching of EXACT and PHRASE custom rules.
 */
export class AhoCorasickAutomaton {
	private nodes: TrieNode[] = [{ children: new Map(), fail: 0, outputs: [] }];
	private built = false;

	public addPattern(pattern: string, output: AutomatonOutput): void {
		if (!pattern) return;
		let current = 0;
		for (let i = 0; i < pattern.length; i++) {
			const ch = pattern[i];
			let next = this.nodes[current].children.get(ch);
			if (next === undefined) {
				next = this.nodes.length;
				this.nodes.push({ children: new Map(), fail: 0, outputs: [] });
				this.nodes[current].children.set(ch, next);
			}
			current = next;
		}
		this.nodes[current].outputs.push(output);
		this.built = false;
	}

	public buildFailureLinks(): void {
		const queue: number[] = [];
		const root = this.nodes[0];

		for (const childIdx of root.children.values()) {
			this.nodes[childIdx].fail = 0;
			queue.push(childIdx);
		}

		let head = 0;
		while (head < queue.length) {
			const currentIdx = queue[head++];
			const currentNode = this.nodes[currentIdx];

			for (const [ch, childIdx] of currentNode.children.entries()) {
				queue.push(childIdx);
				let failCandidate = currentNode.fail;
				while (failCandidate !== 0 && !this.nodes[failCandidate].children.has(ch)) {
					failCandidate = this.nodes[failCandidate].fail;
				}
				const failTarget = this.nodes[failCandidate].children.get(ch) ?? 0;
				this.nodes[childIdx].fail = childIdx === failTarget ? 0 : failTarget;
				if (this.nodes[this.nodes[childIdx].fail].outputs.length > 0) {
					this.nodes[childIdx].outputs = [
						...this.nodes[childIdx].outputs,
						...this.nodes[this.nodes[childIdx].fail].outputs
					];
				}
			}
		}

		this.built = true;
	}

	public search(text: string): Array<{ start: number; end: number; output: AutomatonOutput }> {
		if (this.nodes.length <= 1 || !text) return [];
		if (!this.built) {
			this.buildFailureLinks();
		}

		const matches: Array<{ start: number; end: number; output: AutomatonOutput }> = [];
		let state = 0;

		for (let i = 0; i < text.length; i++) {
			const ch = text[i];
			while (state !== 0 && !this.nodes[state].children.has(ch)) {
				state = this.nodes[state].fail;
			}
			state = this.nodes[state].children.get(ch) ?? 0;

			const outputs = this.nodes[state].outputs;
			if (outputs.length > 0) {
				for (const output of outputs) {
					const end = i + 1;
					const start = end - output.length;
					if (start >= 0) {
						matches.push({ start, end, output });
					}
				}
			}
		}

		return matches;
	}
}

interface CompiledRegexEntry {
	id: string;
	value: string;
	regex: RegExp;
}

/**
 * Custom Rule Compilation & Execution Engine (Aho-Corasick + Pre-compiled SafeRegExp)
 */
export class CustomRuleEngine {
	private caseSensitiveAutomaton = new AhoCorasickAutomaton();
	private caseInsensitiveAutomaton = new AhoCorasickAutomaton();
	private hasCaseSensitivePatterns = false;
	private hasCaseInsensitivePatterns = false;
	private compiledRegexes: CompiledRegexEntry[] = [];

	constructor(rules: CustomRule[] = []) {
		this.compile(rules);
	}

	public compile(rules: CustomRule[]): void {
		this.caseSensitiveAutomaton = new AhoCorasickAutomaton();
		this.caseInsensitiveAutomaton = new AhoCorasickAutomaton();
		this.hasCaseSensitivePatterns = false;
		this.hasCaseInsensitivePatterns = false;
		this.compiledRegexes = [];

		for (const rule of rules) {
			if (!rule || !rule.enabled) continue;
			const validation = validateCustomRule(rule.type, rule.value);
			if (!validation.valid) continue;

			const rawVal = rule.value.trim();
			if (rule.type === 'EXACT' || rule.type === 'PHRASE') {
				const output: AutomatonOutput = {
					id: rule.id,
					type: rule.type,
					value: rawVal,
					length: rawVal.length
				};
				if (rule.caseSensitive) {
					this.caseSensitiveAutomaton.addPattern(rawVal, output);
					this.hasCaseSensitivePatterns = true;
				} else {
					const lowered = rawVal.toLowerCase();
					this.caseInsensitiveAutomaton.addPattern(lowered, {
						...output,
						length: lowered.length
					});
					this.hasCaseInsensitivePatterns = true;
				}
			} else if (rule.type === 'REGEX') {
				try {
					const flags = rule.caseSensitive ? 'g' : 'gi';
					this.compiledRegexes.push({
						id: rule.id,
						value: rawVal,
						regex: new RegExp(rawVal, flags)
					});
				} catch {
					// Ignore invalid regex
				}
			}
		}

		if (this.hasCaseSensitivePatterns) {
			this.caseSensitiveAutomaton.buildFailureLinks();
		}
		if (this.hasCaseInsensitivePatterns) {
			this.caseInsensitiveAutomaton.buildFailureLinks();
		}
	}

	private isWholeWordMatch(text: string, start: number, end: number): boolean {
		const startIsWord = start < text.length && WORD_CHAR_REGEX.test(text[start]);
		const endIsWord = end > 0 && WORD_CHAR_REGEX.test(text[end - 1]);

		if (startIsWord && start > 0 && WORD_CHAR_REGEX.test(text[start - 1])) {
			return false;
		}
		if (endIsWord && end < text.length && WORD_CHAR_REGEX.test(text[end])) {
			return false;
		}
		return true;
	}

	public scan(text: string, config?: Partial<ScanConfig>): RedactionEntity[] {
		if (!text) return [];
		if (!isTypeEnabled('CUSTOM_RULE', config?.enabledTypes)) return [];

		const entities: RedactionEntity[] = [];

		if (this.hasCaseSensitivePatterns) {
			const matches = this.caseSensitiveAutomaton.search(text);
			for (const m of matches) {
				if (m.output.type === 'EXACT' && !this.isWholeWordMatch(text, m.start, m.end)) {
					continue;
				}
				entities.push({
					type: 'CUSTOM_RULE',
					start: m.start,
					end: m.end,
					source: 'CUSTOM',
					confidence: 1.0,
					redacted: true,
					ruleId: m.output.id,
					ruleValue: m.output.value
				});
			}
		}

		if (this.hasCaseInsensitivePatterns) {
			const lowerText = text.toLowerCase();
			// Only use fast-path offsets when lowerText length matches text length
			if (lowerText.length === text.length) {
				const matches = this.caseInsensitiveAutomaton.search(lowerText);
				for (const m of matches) {
					if (m.output.type === 'EXACT' && !this.isWholeWordMatch(text, m.start, m.end)) {
						continue;
					}
					entities.push({
						type: 'CUSTOM_RULE',
						start: m.start,
						end: m.end,
						source: 'CUSTOM',
						confidence: 1.0,
						redacted: true,
						ruleId: m.output.id,
						ruleValue: m.output.value
					});
				}
			}
		}

		for (const entry of this.compiledRegexes) {
			const regex = entry.regex;
			regex.lastIndex = 0;
			const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
			let match: RegExpExecArray | null;
			let iterations = 0;

			while ((match = regex.exec(text)) !== null) {
				const rawMatch = match[0];
				if (rawMatch.length === 0) {
					regex.lastIndex++;
					continue;
				}
				entities.push({
					type: 'CUSTOM_RULE',
					start: match.index,
					end: match.index + rawMatch.length,
					source: 'CUSTOM',
					confidence: 1.0,
					redacted: true,
					ruleId: entry.id,
					ruleValue: entry.value
				});

				iterations++;
				// Guard against excessive execution time (> 5ms budget per custom regex rule)
				const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
				if (now - startTime > 5 || iterations > 5000) {
					break;
				}
			}
		}

		return ConflictResolver.resolve(entities);
	}
}

/**
 * Calculate Shannon Entropy H(X) = - sum P(x_i) log2 P(x_i)
 */
export function calculateShannonEntropy(token: string): number {
	const len = token.length;
	if (len === 0) return 0;

	const counts = new Map<string, number>();
	for (let i = 0; i < len; i++) {
		const ch = token[i];
		counts.set(ch, (counts.get(ch) ?? 0) + 1);
	}

	let entropy = 0;
	for (const count of counts.values()) {
		const p = count / len;
		entropy -= p * Math.log2(p);
	}

	return entropy;
}

/**
 * Validate credit card digits with Luhn check
 */
export function isValidLuhn(raw: string): boolean {
	const digits = raw.replace(/\D/g, '');
	if (digits.length < 13 || digits.length > 19) return false;
	// Reject all-same-digit sequences
	if (/^(\d)\1+$/.test(digits)) return false;

	let sum = 0;
	let shouldDouble = false;
	for (let i = digits.length - 1; i >= 0; i--) {
		let digit = digits.charCodeAt(i) - 48;
		if (shouldDouble) {
			digit *= 2;
			if (digit > 9) digit -= 9;
		}
		sum += digit;
		shouldDouble = !shouldDouble;
	}
	return sum % 10 === 0;
}

export function isSwedishSSNValid(raw: string): boolean {
	// e.g. YYMMDD-XXXX or YYYYMMDD-XXXX, sometimes with '+' instead of '-'
	const digits = raw.replace(/\D/g, '');
	if (digits.length !== 10 && digits.length !== 12) return false;

	if (digits.length === 12) {
		const century = Number(digits.slice(0, 2));
		if (century !== 18 && century !== 19 && century !== 20) return false;
	}

	const ssn10 = digits.length === 12 ? digits.slice(2) : digits;
	const year = Number(ssn10.slice(0, 2));
	const month = Number(ssn10.slice(2, 4));
	const rawDay = Number(ssn10.slice(4, 6));

	if (month < 1 || month > 12) return false;

	// Swedish coordination numbers (samordningsnummer) add 60 to the calendar day
	const day = rawDay > 60 ? rawDay - 60 : rawDay;
	const fullYear = digits.length === 12 ? Number(digits.slice(0, 4)) : 2000 + year;
	const isLeapYear = (fullYear % 4 === 0 && fullYear % 100 !== 0) || fullYear % 400 === 0;
	const daysInMonths = [31, isLeapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
	if (day < 1 || day > daysInMonths[month - 1]) return false;

	let sum = 0;
	let shouldDouble = true; // For 10 digits, we double the first one (weights: 2 1 2 1 2 1 2 1 2 1)
	for (let i = 0; i < ssn10.length; i++) {
		let digit = ssn10.charCodeAt(i) - 48;
		if (shouldDouble) {
			digit *= 2;
			if (digit > 9) digit -= 9;
		}
		sum += digit;
		shouldDouble = !shouldDouble;
	}
	return sum % 10 === 0;
}

const SWEDISH_SSN_REGEX = new RegExp('\\b(?:\\d{2})?\\d{6}[-+]?\\d{4}\\b', 'g');
const SWEDISH_SSN_EXPLICIT_FORMAT_REGEX = new RegExp('\\b(?:\\d{2})?\\d{6}[-+]\\d{4}\\b', 'g');

interface RegexRule {
	type: EntityType;
	rule: RegExp;
	validate?: (match: string) => boolean;
}

const REGEX_RULES: RegexRule[] = [
	{
		type: 'EMAIL',
		rule: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
	},
	{
		type: 'IP',
		// IPv4 (0-255 octets) and standard IPv6
		rule: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g
	},
	{
		type: 'TOKEN',
		// GitHub tokens, OpenAI keys, AWS Access Key IDs, Stripe keys, Slack tokens, JWTs, UUIDs
		rule: /\b(?:gh[pousr]_[A-Za-z0-9_]{36,255}|sk-(?:proj-)?[A-Za-z0-9_-]{20,255}|(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}|(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}|xox[baprs]-[0-9a-zA-Z-]{10,255}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})\b/g
	},
	{
		type: 'CREDIT_CARD',
		rule: /\b(?:\d[ -]*?){13,19}\b/g,
		validate: isValidLuhn
	},
	{
		type: 'SSN',
		rule: SWEDISH_SSN_REGEX,
		validate: isSwedishSSNValid
	}
];

function isTypeEnabled(type: EntityType, enabledTypes?: EntityType[]): boolean {
	if (!enabledTypes || enabledTypes.length === 0) return true;
	if (enabledTypes.includes(type)) return true;
	if (type === 'SUSPECTED_TOKEN' && enabledTypes.includes('TOKEN')) return true;
	if (type === 'AMBIGUOUS_PER' && enabledTypes.includes('PER')) return true;
	if (type === 'AMBIGUOUS_ORG' && enabledTypes.includes('ORG')) return true;
	return false;
}

/**
 * Stage 1: Deterministic Regex & High-Entropy Scanner
 */
export class RegexEngine {
	public static scan(text: string, config?: Partial<ScanConfig>): RedactionEntity[] {
		if (!text) return [];
		const enabledTypes = config?.enabledTypes;
		const entities: RedactionEntity[] = [];

		for (const { type, rule, validate } of REGEX_RULES) {
			if (!isTypeEnabled(type, enabledTypes)) continue;

			rule.lastIndex = 0;
			const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
			let match: RegExpExecArray | null;
			let iterations = 0;

			while ((match = rule.exec(text)) !== null) {
				const rawMatch = match[0];
				if (rawMatch.length === 0) {
					rule.lastIndex++;
					continue;
				}
				if (!validate || validate(rawMatch)) {
					entities.push({
						type,
						start: match.index,
						end: match.index + rawMatch.length,
						source: 'REGEX',
						confidence: 1.0,
						redacted: true
					});
				}

				iterations++;
				// Guard against excessive execution time (> 5ms budget per pattern check)
				const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
				if (now - startTime > 5 || iterations > 5000) {
					break;
				}
			}
		}

		// High-Entropy Token Scanner (Phase 2.4.2):
		// Apply Shannon Entropy to tokens without whitespace exceeding 16 characters.
		// If H(X) > 4.5 and alphanumeric, classify as SUSPECTED_TOKEN.
		if (isTypeEnabled('SUSPECTED_TOKEN', enabledTypes)) {
			const tokenRegex = /\S+/g;
			let tokenMatch: RegExpExecArray | null;
			while ((tokenMatch = tokenRegex.exec(text)) !== null) {
				const rawToken = tokenMatch[0];
				// Strip leading/trailing punctuation
				const leadTrim = rawToken.match(/^[^A-Za-z0-9]+/)?.[0].length ?? 0;
				const trailTrim = rawToken.match(/[^A-Za-z0-9]+$/)?.[0].length ?? 0;
				const cleanStart = tokenMatch.index + leadTrim;
				const cleanEnd = tokenMatch.index + rawToken.length - trailTrim;
				if (cleanEnd <= cleanStart) continue;

				const candidate = text.slice(cleanStart, cleanEnd);
				if (candidate.length <= 16) continue;

				// Must be alphanumeric (with optional -/_ connectors common in secret tokens) and contain both letters & digits or mixed case
				if (!/^[A-Za-z0-9_-]+$/.test(candidate)) continue;
				if (!/[A-Za-z]/.test(candidate) || !/[0-9]/.test(candidate)) continue;

				// Skip if already covered by a deterministic regex entity
				const alreadyMatched = entities.some((e) => cleanStart < e.end && cleanEnd > e.start);
				if (alreadyMatched) continue;

				const entropy = calculateShannonEntropy(candidate);
				if (entropy > 4.5) {
					entities.push({
						type: 'SUSPECTED_TOKEN',
						start: cleanStart,
						end: cleanEnd,
						source: 'REGEX',
						confidence: Math.min(0.99, Number((entropy / 6.0).toFixed(2))),
						redacted: true
					});
				}
			}
		}

		return ConflictResolver.resolve(entities);
	}
}

/**
 * Zero-mask regex matches, custom rule matches, and synthetic noise (hex hashes, stack traces) with spaces
 * so the NER model never evaluates already-finalized or synthetic tokens while preserving 1:1 character offsets.
 */
export function createZeroMaskedBuffer(text: string, priorEntities: RedactionEntity[]): string {
	if (!text) return '';
	const chars = text.split('');

	const maskRange = (start: number, end: number) => {
		const clampedStart = Math.max(0, start);
		const clampedEnd = Math.min(chars.length, end);
		for (let i = clampedStart; i < clampedEnd; i++) {
			if (chars[i] !== '\n' && chars[i] !== '\r') {
				chars[i] = ' ';
			}
		}
	};

	for (const entity of priorEntities) {
		maskRange(entity.start, entity.end);
	}

	// Also strip high-density non-natural patterns (e.g. hex hashes >= 16 chars, stack trace frames)
	const syntheticPatterns = [/\b[0-9a-fA-F]{16,64}\b/g, /^\s*at\s+[^\n]+$/gm];
	for (const pattern of syntheticPatterns) {
		let m: RegExpExecArray | null;
		while ((m = pattern.exec(text)) !== null) {
			maskRange(m.index, m.index + m[0].length);
		}
	}

	return chars.join('');
}

export interface TextChunk {
	text: string;
	startOffset: number;
	endOffset: number;
}

/**
 * Split raw text into sliding window chunks (default 384 words/tokens with 64-token stride)
 * preserving exact character offsets.
 */
export function splitIntoChunks(text: string, maxTokens = 384, strideTokens = 64): TextChunk[] {
	if (!text) return [];

	const wordSpans: Array<{ start: number; end: number }> = [];
	const wordRegex = /\S+/g;
	let match: RegExpExecArray | null;
	while ((match = wordRegex.exec(text)) !== null) {
		wordSpans.push({ start: match.index, end: match.index + match[0].length });
	}

	if (wordSpans.length === 0) {
		return [];
	}

	if (wordSpans.length <= maxTokens) {
		return [{ text, startOffset: 0, endOffset: text.length }];
	}

	const step = Math.max(1, maxTokens - strideTokens);
	const chunks: TextChunk[] = [];

	for (let i = 0; i < wordSpans.length; i += step) {
		const startWord = wordSpans[i];
		const endWordIdx = Math.min(i + maxTokens - 1, wordSpans.length - 1);
		const endWord = wordSpans[endWordIdx];

		const startOffset = i === 0 ? 0 : startWord.start;
		const endOffset = endWordIdx === wordSpans.length - 1 ? text.length : endWord.end;

		chunks.push({
			text: text.slice(startOffset, endOffset),
			startOffset,
			endOffset
		});

		if (endWordIdx === wordSpans.length - 1) break;
	}

	return chunks;
}

/**
 * Determine whether a chunk should bypass the neural NER model:
 * - Zero alphabetical characters
 * - 100% structured JSON / code block payload
 */
export function shouldSkipChunk(chunkText: string): boolean {
	const trimmed = chunkText.trim();
	if (!trimmed) return true;

	// Zero alphabetical characters
	if (!/\p{L}/u.test(trimmed)) return true;

	// Structured JSON object or array
	if (
		(trimmed.startsWith('{') && trimmed.endsWith('}')) ||
		(trimmed.startsWith('[') && trimmed.endsWith(']'))
	) {
		try {
			const parsed = JSON.parse(trimmed);
			if (typeof parsed === 'object' && parsed !== null) {
				return true;
			}
		} catch {
			// Not pure JSON, continue checking
		}
	}

	return false;
}

/**
 * Clamp entity boundaries strictly to whole-word unicode boundaries (\b),
 * preventing partial-word redaction like `[NAME]ing`.
 */
export function clampToWordBoundaries(
	text: string,
	start: number,
	end: number
): { start: number; end: number } {
	let s = Math.max(0, Math.min(text.length, start));
	let e = Math.max(s, Math.min(text.length, end));

	// Trim leading and trailing whitespace
	while (s < e && /\s/.test(text[s])) s++;
	while (e > s && /\s/.test(text[e - 1])) e--;

	// Trim leading/trailing punctuation that isn't part of a word
	while (s < e && !WORD_CHAR_REGEX.test(text[s])) s++;
	while (e > s && !WORD_CHAR_REGEX.test(text[e - 1])) e--;

	if (s >= e) {
		return { start: s, end: e };
	}

	// Expand outward to whole-word unicode boundaries if a subword split inside a word
	while (s > 0 && WORD_CHAR_REGEX.test(text[s - 1])) {
		s--;
	}
	while (e < text.length && WORD_CHAR_REGEX.test(text[e])) {
		e++;
	}

	return { start: s, end: e };
}

export interface RawNerToken {
	entity?: string;
	entity_group?: string;
	score: number;
	index?: number;
	word?: string;
	start?: number;
	end?: number;
}

/**
 * Align raw NER tokens from @huggingface/transformers to character offsets in the source text,
 * merge consecutive B-/I- tags and WordPiece `##` subwords, clamp to whole-word boundaries,
 * and apply Ambiguous PII rules (confidence 0.40 - 0.75 or context-dependent proper nouns).
 */
export function alignAndNormalizeNerTokens(
	rawTokens: RawNerToken[],
	chunkText: string,
	chunkOffset: number,
	fullText: string,
	config?: Partial<ScanConfig>
): RedactionEntity[] {
	if (!rawTokens || rawTokens.length === 0) return [];

	const aggressiveMode = config?.aggressiveMode ?? false;
	const enabledTypes = config?.enabledTypes;

	interface AlignedToken {
		prefix: 'B' | 'I' | 'E' | 'S';
		baseType: 'PER' | 'ORG' | 'LOC';
		start: number;
		end: number;
		score: number;
		isSubword: boolean;
		index?: number;
	}

	const aligned: AlignedToken[] = [];
	let searchCursor = 0;

	for (const raw of rawTokens) {
		const rawLabel = raw.entity ?? raw.entity_group ?? '';
		if (!rawLabel || rawLabel === 'O') continue;

		const prefixMatch = rawLabel.match(/^([BIES])-(.+)$/);
		const prefix = (prefixMatch ? prefixMatch[1] : 'B') as 'B' | 'I' | 'E' | 'S';
		const tag = (prefixMatch ? prefixMatch[2] : rawLabel).toUpperCase();

		if (tag !== 'PER' && tag !== 'ORG' && tag !== 'LOC') continue;

		const rawWord = raw.word ?? '';
		const isSubword = rawWord.startsWith('##');
		const cleanWord = rawWord.replace(/^##/, '').trim();

		let localStart: number | undefined =
			typeof raw.start === 'number' && !Number.isNaN(raw.start) ? raw.start : undefined;
		let localEnd: number | undefined =
			typeof raw.end === 'number' && !Number.isNaN(raw.end) ? raw.end : undefined;

		if (localStart === undefined || localEnd === undefined) {
			if (!cleanWord) continue;
			let foundIdx = chunkText.indexOf(cleanWord, searchCursor);
			if (foundIdx === -1) {
				// Case-insensitive fallback if tokenizer lowercased/normalized accents
				const lowerChunk = chunkText.toLowerCase();
				foundIdx = lowerChunk.indexOf(cleanWord.toLowerCase(), searchCursor);
			}
			if (foundIdx === -1) continue;

			localStart = foundIdx;
			localEnd = foundIdx + cleanWord.length;
			searchCursor = localEnd;
		} else {
			searchCursor = Math.max(searchCursor, localEnd);
		}

		aligned.push({
			prefix,
			baseType: tag,
			start: chunkOffset + localStart,
			end: chunkOffset + localEnd,
			score: raw.score ?? 0.5,
			isSubword,
			index: raw.index
		});
	}

	if (aligned.length === 0) return [];

	// Merge consecutive BIO / subword tokens into spans
	interface MergedSpan {
		baseType: 'PER' | 'ORG' | 'LOC';
		start: number;
		end: number;
		scores: number[];
		lastIndex?: number;
	}

	const mergedSpans: MergedSpan[] = [];

	for (const tok of aligned) {
		const prev = mergedSpans[mergedSpans.length - 1];
		if (prev) {
			const gapText = fullText.slice(prev.end, tok.start);
			const isAdjacentInText =
				tok.start >= prev.start && (tok.start <= prev.end || /^[ \t]*$/.test(gapText));
			const isConsecutiveToken =
				prev.lastIndex === undefined || tok.index === undefined || tok.index === prev.lastIndex + 1;
			const sameWordContinuation = tok.start === prev.end && tok.isSubword;
			const bioContinuation =
				tok.baseType === prev.baseType &&
				(tok.prefix === 'I' || tok.prefix === 'E' || tok.isSubword) &&
				isAdjacentInText &&
				isConsecutiveToken;

			if (sameWordContinuation || bioContinuation) {
				prev.end = Math.max(prev.end, tok.end);
				prev.scores.push(tok.score);
				prev.lastIndex = tok.index;
				continue;
			}
		}

		mergedSpans.push({
			baseType: tok.baseType,
			start: tok.start,
			end: tok.end,
			scores: [tok.score],
			lastIndex: tok.index
		});
	}

	// Clamp to whole-word boundaries & classify ambiguous spans
	const results: RedactionEntity[] = [];

	for (const span of mergedSpans) {
		const avgScore = span.scores.reduce((sum, val) => sum + val, 0) / span.scores.length;

		// Ignore noise below 0.40 confidence unless aggressiveMode is active
		if (avgScore < 0.4 && !aggressiveMode) continue;

		const clamped = clampToWordBoundaries(fullText, span.start, span.end);
		if (clamped.end <= clamped.start) continue;

		const surfaceWord = fullText.slice(clamped.start, clamped.end).trim();
		if (!surfaceWord) continue;

		const isKnownAmbiguousNoun =
			!surfaceWord.includes(' ') && AMBIGUOUS_PROPER_NOUNS.has(surfaceWord.toLowerCase());
		const isMediumConfidence = avgScore >= 0.4 && avgScore <= 0.75;
		const isAmbiguous =
			(span.baseType === 'PER' || span.baseType === 'ORG') &&
			(isMediumConfidence || (isKnownAmbiguousNoun && avgScore < 0.9));

		let finalType: EntityType = span.baseType;
		let redacted = true;

		if (isAmbiguous) {
			finalType = span.baseType === 'PER' ? 'AMBIGUOUS_PER' : 'AMBIGUOUS_ORG';
			redacted = aggressiveMode;
		}

		if (!isTypeEnabled(finalType, enabledTypes)) continue;

		results.push({
			type: finalType,
			start: clamped.start,
			end: clamped.end,
			source: 'NER',
			confidence: Number(avgScore.toFixed(4)),
			ambiguous: isAmbiguous,
			redacted
		});
	}

	return results;
}

/**
 * Stage 3: Conflict Resolution and Boundary Clamping
 * Precedence Hierarchy:
 * 1. Built-in Hard Regex (source === 'REGEX') - Highest priority
 * 2. User Custom Rules (source === 'CUSTOM') - Second priority (overrides general AI detections)
 * 3. Probabilistic NER (source === 'NER') - Lowest priority
 */
export class ConflictResolver {
	public static resolve(entities: RedactionEntity[]): RedactionEntity[] {
		if (entities.length <= 1) {
			return [...entities];
		}

		const regexEntities = entities
			.filter((e) => e.source === 'REGEX')
			.sort((a, b) => a.start - b.start || b.end - a.end);

		// Deduplicate/resolve overlapping Regex entities (Longest match wins)
		const resolvedRegex: RedactionEntity[] = [];
		for (const candidate of regexEntities) {
			const existingIdx = resolvedRegex.findIndex(
				(e) => candidate.start < e.end && candidate.end > e.start
			);
			if (existingIdx === -1) {
				resolvedRegex.push({ ...candidate });
			} else {
				const existing = resolvedRegex[existingIdx];
				const candidateLen = candidate.end - candidate.start;
				const existingLen = existing.end - existing.start;
				// Deterministic specific regex beats SUSPECTED_TOKEN; otherwise longest match wins
				const candidateIsSpecific = candidate.type !== 'SUSPECTED_TOKEN';
				const existingIsSpecific = existing.type !== 'SUSPECTED_TOKEN';
				if (
					(candidateIsSpecific && !existingIsSpecific) ||
					(candidateIsSpecific === existingIsSpecific && candidateLen > existingLen)
				) {
					resolvedRegex[existingIdx] = { ...candidate };
				}
			}
		}

		// Tier 2: Custom Rules (yield to Built-in Hard Regex; longest match wins among overlapping custom rules)
		const customEntities = entities
			.filter((e) => e.source === 'CUSTOM')
			.sort((a, b) => a.start - b.start || b.end - a.end);

		const nonCollidingCustom = customEntities.filter(
			(custom) => !resolvedRegex.some((reg) => custom.start < reg.end && custom.end > reg.start)
		);

		const resolvedCustom: RedactionEntity[] = [];
		for (const candidate of nonCollidingCustom) {
			const existingIdx = resolvedCustom.findIndex(
				(e) => candidate.start < e.end && candidate.end > e.start
			);
			if (existingIdx === -1) {
				resolvedCustom.push({ ...candidate });
			} else {
				const existing = resolvedCustom[existingIdx];
				if (candidate.end - candidate.start > existing.end - existing.start) {
					resolvedCustom[existingIdx] = { ...candidate };
				}
			}
		}

		// Tier 3: Probabilistic NER (yields to both Built-in Hard Regex and User Custom Rules)
		const nerEntities = entities
			.filter((e) => e.source === 'NER')
			.sort((a, b) => a.start - b.start || b.end - a.end);

		const higherPriority = [...resolvedRegex, ...resolvedCustom];
		const nonCollidingNer = nerEntities.filter(
			(ner) => !higherPriority.some((hp) => ner.start < hp.end && ner.end > hp.start)
		);

		// Merge overlapping or identical NER entities from sliding window chunks & resolve collisions
		const resolvedNer: RedactionEntity[] = [];
		for (const candidate of nonCollidingNer) {
			const overlapIdx = resolvedNer.findIndex(
				(e) => candidate.start < e.end && candidate.end > e.start
			);

			if (overlapIdx === -1) {
				resolvedNer.push({ ...candidate });
				continue;
			}

			const existing = resolvedNer[overlapIdx];
			const candidateLen = candidate.end - candidate.start;
			const existingLen = existing.end - existing.start;

			// If same base category across chunk boundary, merge union span if confidence is high
			const normalizeBase = (t: EntityType) => t.replace(/^AMBIGUOUS_/, '');
			if (normalizeBase(candidate.type) === normalizeBase(existing.type)) {
				if (candidateLen > existingLen && candidate.confidence > 0.8) {
					resolvedNer[overlapIdx] = {
						...candidate,
						start: Math.min(existing.start, candidate.start),
						end: Math.max(existing.end, candidate.end)
					};
				} else if (existingLen >= candidateLen && existing.confidence > 0.8) {
					resolvedNer[overlapIdx] = {
						...existing,
						start: Math.min(existing.start, candidate.start),
						end: Math.max(existing.end, candidate.end)
					};
				} else if (candidateLen > existingLen) {
					resolvedNer[overlapIdx] = { ...candidate };
				}
			} else {
				// Different NER categories overlapping: longer span or higher confidence (> 0.80) wins
				if (
					(candidateLen > existingLen && candidate.confidence >= 0.8) ||
					(candidateLen === existingLen && candidate.confidence > existing.confidence)
				) {
					resolvedNer[overlapIdx] = { ...candidate };
				}
			}
		}

		return [...resolvedRegex, ...resolvedCustom, ...resolvedNer].sort(
			(a, b) => a.start - b.start || b.end - a.end
		);
	}
}

/**
 * Compact numeric buffer serialization for postMessage transfer (Phase 2.1 Bottleneck 1)
 * Stride = 6 integers per entity:
 * [typeEnum, start, end, sourceEnum (1=REGEX, 2=NER, 3=CUSTOM), confidenceScaled (0..10000), flags (bit0=ambiguous, bit1=redacted)]
 */
const BUFFER_STRIDE = 6;

export function encodeEntitiesToBuffer(entities: RedactionEntity[]): Int32Array {
	const buffer = new Int32Array(entities.length * BUFFER_STRIDE);
	for (let i = 0; i < entities.length; i++) {
		const e = entities[i];
		const offset = i * BUFFER_STRIDE;
		buffer[offset] = ENTITY_TYPE_TO_ENUM[e.type] ?? 1;
		buffer[offset + 1] = e.start;
		buffer[offset + 2] = e.end;
		buffer[offset + 3] = e.source === 'REGEX' ? 1 : e.source === 'CUSTOM' ? 3 : 2;
		buffer[offset + 4] = Math.round((e.confidence ?? 1) * 10000);
		const flags = (e.ambiguous ? 1 : 0) | (e.redacted !== false ? 2 : 0);
		buffer[offset + 5] = flags;
	}
	return buffer;
}

export function decodeEntitiesFromBuffer(buffer: Int32Array): RedactionEntity[] {
	const entities: RedactionEntity[] = [];
	for (let offset = 0; offset + BUFFER_STRIDE <= buffer.length; offset += BUFFER_STRIDE) {
		const type = ENUM_TO_ENTITY_TYPE[buffer[offset]] ?? 'PER';
		const start = buffer[offset + 1];
		const end = buffer[offset + 2];
		const sourceCode = buffer[offset + 3];
		const source = sourceCode === 1 ? 'REGEX' : sourceCode === 3 ? 'CUSTOM' : 'NER';
		const confidence = buffer[offset + 4] / 10000;
		const flags = buffer[offset + 5];
		const ambiguous = (flags & 1) !== 0;
		const redacted = (flags & 2) !== 0;

		entities.push({
			type,
			start,
			end,
			source,
			confidence,
			...(ambiguous ? { ambiguous: true } : {}),
			redacted
		});
	}
	return entities;
}

/**
 * Apply redactions to raw text using safe default substitutions ([NAME], [ORG], [IP], [CUSTOM], etc.)
 */
export function applyRedactions(text: string, entities: RedactionEntity[]): string {
	if (!text || !entities || entities.length === 0) return text;

	const sorted = [...entities].sort((a, b) => a.start - b.start);
	let result = '';
	let lastIndex = 0;

	for (const entity of sorted) {
		if (entity.redacted === false) continue;
		if (
			typeof entity.start !== 'number' ||
			typeof entity.end !== 'number' ||
			Number.isNaN(entity.start) ||
			Number.isNaN(entity.end)
		) {
			continue;
		}
		if (entity.start < lastIndex || entity.end <= entity.start) continue;

		result += text.slice(lastIndex, entity.start);
		result += REDACTION_LABELS[entity.type] ?? `[${entity.type}]`;
		lastIndex = entity.end;
	}
	result += text.slice(lastIndex);

	return result;
}

/**
 * Phase 2.4.3: Masked Redaction Verification (Double-Check Step)
 * Checks sanitized output for residual sensitive patterns such as unmasked SSNs.
 */
export interface VerificationResult {
	valid: boolean;
	warnings: string[];
}

const RESIDUAL_SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/;

export function buildVerificationReports(
	text: string,
	entities: RedactionEntity[],
	executionTimeMs: number,
	config?: Partial<ScanConfig>
): VerificationReport[] {
	if (!text || !text.trim()) return [];
	if (!isTypeEnabled('SSN', config?.enabledTypes)) return [];

	const ssnMatches = entities.filter((e) => e.type === 'SSN');
	const boundedTimeMs = Math.max(0, Math.round(executionTimeMs));

	if (ssnMatches.length > 0) {
		return [
			{
				ruleId: 'swedish-ssn-check',
				status: 'DETECTED',
				matchesCount: ssnMatches.length,
				executionTimeMs: boundedTimeMs,
				message: `SSN Pattern Detected - ${ssnMatches.length} Masked`
			}
		];
	}

	SWEDISH_SSN_EXPLICIT_FORMAT_REGEX.lastIndex = 0;
	const checkStart = typeof performance !== 'undefined' ? performance.now() : Date.now();
	let candidateMatch: RegExpExecArray | null;
	let hasInvalidFormatCandidate = false;
	let iterations = 0;

	while ((candidateMatch = SWEDISH_SSN_EXPLICIT_FORMAT_REGEX.exec(text)) !== null) {
		if (!isSwedishSSNValid(candidateMatch[0])) {
			hasInvalidFormatCandidate = true;
			break;
		}
		iterations++;
		const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
		if (now - checkStart > 5 || iterations > 5000) {
			break;
		}
	}

	if (hasInvalidFormatCandidate) {
		return [
			{
				ruleId: 'swedish-ssn-check',
				status: 'INVALID_FORMAT',
				matchesCount: 0,
				executionTimeMs: boundedTimeMs,
				message: 'SSN Pattern Invalid Format - Checksum Failed'
			}
		];
	}

	return [
		{
			ruleId: 'swedish-ssn-check',
			status: 'NOT_DETECTED',
			matchesCount: 0,
			executionTimeMs: boundedTimeMs,
			message: 'SSN Pattern Checked - 0 Found'
		}
	];
}

export function verifySanitizedText(sanitizedText: string): VerificationResult {
	const warnings: string[] = [];

	let hasResidualSwedishSsn = false;
	SWEDISH_SSN_REGEX.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = SWEDISH_SSN_REGEX.exec(sanitizedText)) !== null) {
		if (isSwedishSSNValid(match[0])) {
			hasResidualSwedishSsn = true;
			break;
		}
	}

	if (RESIDUAL_SSN_REGEX.test(sanitizedText) || hasResidualSwedishSsn) {
		warnings.push('Potential unmasked SSN detected.');
	}

	return {
		valid: warnings.length === 0,
		warnings
	};
}

export interface HighlightSegment {
	text: string;
	entity?: RedactionEntity;
	entityIndex?: number;
}

/**
 * Compute the character offset window corresponding to the current scroll viewport + 200px buffer
 * (Phase 2.1 Bottleneck 3: Virtualized Viewport Slicing).
 */
export function getViewportCharRange(
	text: string,
	scrollTop: number,
	viewportHeight: number,
	lineHeight = 21,
	bufferPx = 200
): { startChar: number; endChar: number } {
	if (!text) return { startChar: 0, endChar: 0 };

	const topPx = Math.max(0, scrollTop - bufferPx);
	const bottomPx = scrollTop + Math.max(viewportHeight, 256) + bufferPx;

	const startLine = Math.max(0, Math.floor(topPx / lineHeight));
	const endLine = Math.ceil(bottomPx / lineHeight);

	// Estimate ~80 chars per wrapped line as a minimum window so long single-line logs also slice safely
	let currentLine = 0;
	let startChar = 0;
	let foundStart = startLine === 0;

	for (let i = 0; i < text.length; i++) {
		if (!foundStart && currentLine >= startLine) {
			startChar = i;
			foundStart = true;
		}
		if (text[i] === '\n') {
			currentLine++;
			if (currentLine > endLine) {
				return { startChar, endChar: i };
			}
		}
	}

	return { startChar: foundStart ? startChar : 0, endChar: text.length };
}

/**
 * Build declarative highlight segments for the twin-layer overlay.
 * Only entities intersecting the active viewport + 200px buffer are converted into highlight spans;
 * off-screen text remains raw strings.
 */
export function buildHighlightSegments(
	text: string,
	entities: RedactionEntity[],
	viewportRange?: { startChar: number; endChar: number }
): HighlightSegment[] {
	if (!text) return [];
	if (!entities || entities.length === 0) {
		return [{ text }];
	}

	const vpStart = viewportRange?.startChar ?? 0;
	const vpEnd = viewportRange?.endChar ?? text.length;

	const segments: HighlightSegment[] = [];
	let lastIndex = 0;

	for (let i = 0; i < entities.length; i++) {
		const entity = entities[i];
		if (
			typeof entity.start !== 'number' ||
			typeof entity.end !== 'number' ||
			entity.start < lastIndex ||
			entity.end <= entity.start ||
			entity.end > text.length
		) {
			continue;
		}

		// Virtualized check: skip span creation for entities completely outside viewport + buffer
		const isInsideViewport = entity.end >= vpStart && entity.start <= vpEnd;
		if (!isInsideViewport) {
			continue;
		}

		if (entity.start > lastIndex) {
			segments.push({ text: text.slice(lastIndex, entity.start) });
		}

		segments.push({
			text: text.slice(entity.start, entity.end),
			entity,
			entityIndex: i
		});
		lastIndex = entity.end;
	}

	if (lastIndex < text.length) {
		segments.push({ text: text.slice(lastIndex) });
	}

	return segments;
}
