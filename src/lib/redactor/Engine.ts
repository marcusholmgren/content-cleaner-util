import type { EntityType, RedactionEntity, ScanConfig } from './types';

export const DEFAULT_ENABLED_TYPES: EntityType[] = [
	'PER',
	'ORG',
	'LOC',
	'EMAIL',
	'TOKEN',
	'IP',
	'CREDIT_CARD',
	'SUSPECTED_TOKEN',
	'AMBIGUOUS_PER',
	'AMBIGUOUS_ORG'
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
	CREDIT_CARD: '[CREDIT_CARD]'
};

const ENTITY_TYPE_TO_ENUM: Record<EntityType, number> = {
	PER: 1,
	ORG: 2,
	LOC: 3,
	EMAIL: 4,
	TOKEN: 5,
	IP: 6,
	CREDIT_CARD: 7,
	SUSPECTED_TOKEN: 8,
	AMBIGUOUS_PER: 9,
	AMBIGUOUS_ORG: 10
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
	10: 'AMBIGUOUS_ORG'
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

			const regex = new RegExp(rule.source, rule.flags);
			let match: RegExpExecArray | null;
			while ((match = regex.exec(text)) !== null) {
				const rawMatch = match[0];
				if (validate && !validate(rawMatch)) continue;

				entities.push({
					type,
					start: match.index,
					end: match.index + rawMatch.length,
					source: 'REGEX',
					confidence: 1.0,
					redacted: true
				});
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
 * Zero-mask regex matches and synthetic noise (hex hashes, stack traces) with spaces
 * so the NER model never evaluates synthetic tokens while preserving 1:1 character offsets.
 */
export function createZeroMaskedBuffer(text: string, regexEntities: RedactionEntity[]): string {
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

	for (const entity of regexEntities) {
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
 * 1. Absolute Priority: REGEX > NER
 * 2. Span Collisions: Longest-Match vs Class Supremacy (wider span wins; for NER vs dictionary ORG, confidence > 0.80)
 * 3. Cross-chunk deduplication and adjoining entity merging
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

		// Filter & merge NER entities
		const nerEntities = entities
			.filter((e) => e.source === 'NER')
			.sort((a, b) => a.start - b.start || b.end - a.end);

		// 1. Discard any NER entity that collides (even partially) with a Regex entity
		const nonCollidingNer = nerEntities.filter(
			(ner) => !resolvedRegex.some((reg) => ner.start < reg.end && ner.end > reg.start)
		);

		// 2. Merge overlapping or identical NER entities from sliding window chunks & resolve collisions
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

		return [...resolvedRegex, ...resolvedNer].sort((a, b) => a.start - b.start || b.end - a.end);
	}
}

/**
 * Compact numeric buffer serialization for postMessage transfer (Phase 2.1 Bottleneck 1)
 * Stride = 6 integers per entity:
 * [typeEnum, start, end, sourceEnum (1=REGEX, 2=NER), confidenceScaled (0..10000), flags (bit0=ambiguous, bit1=redacted)]
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
		buffer[offset + 3] = e.source === 'REGEX' ? 1 : 2;
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
		const source = buffer[offset + 3] === 1 ? 'REGEX' : 'NER';
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
 * Apply redactions to raw text using safe default substitutions ([NAME], [ORG], [IP], etc.)
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

export function verifySanitizedText(sanitizedText: string): VerificationResult {
	const warnings: string[] = [];

	if (RESIDUAL_SSN_REGEX.test(sanitizedText)) {
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
