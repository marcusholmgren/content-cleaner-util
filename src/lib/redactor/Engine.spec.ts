import { describe, expect, it } from 'vitest';
import {
	ConflictResolver,
	RegexEngine,
	alignAndNormalizeNerTokens,
	applyRedactions,
	buildHighlightSegments,
	calculateShannonEntropy,
	clampToWordBoundaries,
	createZeroMaskedBuffer,
	decodeEntitiesFromBuffer,
	encodeEntitiesToBuffer,
	getViewportCharRange,
	shouldSkipChunk,
	splitIntoChunks,
	verifySanitizedText
} from './Engine';

describe('RegexEngine & Shannon Entropy', () => {
	it('detects emails, IPs, tokens, and valid credit cards', () => {
		const text =
			'Contact john.doe@company.com from 192.168.1.1 with key ghp_1234567890abcdefghijklmnopqrstuvwxyz or card 4532-0151-1283-0366.';
		const entities = RegexEngine.scan(text);

		expect(entities.map((e) => e.type)).toEqual(['EMAIL', 'IP', 'TOKEN', 'CREDIT_CARD']);
		expect(text.slice(entities[0].start, entities[0].end)).toBe('john.doe@company.com');
		expect(text.slice(entities[1].start, entities[1].end)).toBe('192.168.1.1');
		expect(text.slice(entities[2].start, entities[2].end)).toBe(
			'ghp_1234567890abcdefghijklmnopqrstuvwxyz'
		);
		expect(text.slice(entities[3].start, entities[3].end)).toBe('4532-0151-1283-0366');
	});

	it('detects high-entropy unknown secrets (>16 chars, H(X) > 4.5) as SUSPECTED_TOKEN', () => {
		const secret = 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz9';
		expect(calculateShannonEntropy(secret)).toBeGreaterThan(4.5);

		const text = `Bearer token is ${secret} in production`;
		const entities = RegexEngine.scan(text);
		expect(entities).toHaveLength(1);
		expect(entities[0].type).toBe('SUSPECTED_TOKEN');
		expect(text.slice(entities[0].start, entities[0].end)).toBe(secret);
	});
});

describe('Zero-Masking, Sliding Window Chunking & Chunk Skipping', () => {
	it('zero-masks regex matches while preserving exact string length and character offsets', () => {
		const text = 'Server 10.0.0.1 alerted admin@example.com for Alice Smith';
		const regexEntities = RegexEngine.scan(text);
		const masked = createZeroMaskedBuffer(text, regexEntities);

		expect(masked.length).toBe(text.length);
		expect(masked).not.toContain('10.0.0.1');
		expect(masked).not.toContain('admin@example.com');
		expect(masked.indexOf('Alice Smith')).toBe(text.indexOf('Alice Smith'));
	});

	it('splits long text into overlapping sliding window chunks with accurate offsets', () => {
		const words = Array.from({ length: 500 }, (_, i) => `word${i}`);
		const text = words.join(' ');
		const chunks = splitIntoChunks(text, 384, 64);

		expect(chunks.length).toBe(2);
		expect(chunks[0].startOffset).toBe(0);
		expect(chunks[1].startOffset).toBeLessThan(chunks[0].endOffset);
		expect(text.slice(chunks[1].startOffset, chunks[1].endOffset)).toBe(chunks[1].text);
	});

	it('skips chunks with zero alphabetical characters or pure JSON payloads', () => {
		expect(shouldSkipChunk('12345 67890 --- === 0000')).toBe(true);
		expect(shouldSkipChunk('{"level": 30, "time": 1700000, "msg": "ok"}')).toBe(true);
		expect(shouldSkipChunk('Alice met Bob at Acme Corp.')).toBe(false);
	});
});

describe('NER Alignment, Subword Merging, Boundary Clamping & Ambiguous PII', () => {
	it('aligns tokens lacking start/end offsets and merges B-/I- and ## subword tokens', () => {
		const text = 'My name is Sarah Connor from Cyberdyne Systems';
		const rawTokens = [
			{ entity: 'B-PER', score: 0.98, index: 4, word: 'Sa' },
			{ entity: 'I-PER', score: 0.96, index: 5, word: '##rah' },
			{ entity: 'I-PER', score: 0.97, index: 6, word: 'Connor' },
			{ entity: 'B-ORG', score: 0.92, index: 8, word: 'Cyberdyne' },
			{ entity: 'I-ORG', score: 0.94, index: 9, word: 'Systems' }
		];

		const entities = alignAndNormalizeNerTokens(rawTokens, text, 0, text);
		expect(entities).toHaveLength(2);
		expect(entities[0]).toMatchObject({
			type: 'PER',
			start: 11,
			end: 23,
			source: 'NER',
			redacted: true
		});
		expect(text.slice(entities[0].start, entities[0].end)).toBe('Sarah Connor');
		expect(text.slice(entities[1].start, entities[1].end)).toBe('Cyberdyne Systems');
	});

	it('clamps partial subword matches to whole-word unicode boundaries', () => {
		const text = 'Working with Networking systems';
		const clamped = clampToWordBoundaries(text, 13, 20); // "Network" inside "Networking"
		expect(text.slice(clamped.start, clamped.end)).toBe('Networking');
	});

	it('tags medium-confidence (0.40 - 0.75) or ambiguous proper nouns as AMBIGUOUS_* without auto-redacting', () => {
		const text = 'She bought an Apple laptop in May';
		const rawTokens = [
			{ entity: 'B-ORG', score: 0.62, index: 4, word: 'Apple' },
			{ entity: 'B-PER', score: 0.55, index: 7, word: 'May' }
		];

		const normalEntities = alignAndNormalizeNerTokens(rawTokens, text, 0, text, {
			aggressiveMode: false
		});
		expect(normalEntities[0].type).toBe('AMBIGUOUS_ORG');
		expect(normalEntities[0].ambiguous).toBe(true);
		expect(normalEntities[0].redacted).toBe(false);
		expect(normalEntities[1].type).toBe('AMBIGUOUS_PER');
		expect(normalEntities[1].redacted).toBe(false);

		// When un-toggled, applyRedactions preserves ambiguous text
		expect(applyRedactions(text, normalEntities)).toBe(text);

		// In aggressive mode, ambiguous entities are redacted automatically
		const aggressiveEntities = alignAndNormalizeNerTokens(rawTokens, text, 0, text, {
			aggressiveMode: true
		});
		expect(aggressiveEntities[0].redacted).toBe(true);
		expect(applyRedactions(text, aggressiveEntities)).toBe('She bought an [ORG] laptop in [NAME]');
	});
});

describe('ConflictResolver & Precedence Hierarchy', () => {
	it('enforces Regex > NER priority and subsumes overlapping spans (e.g. PER inside EMAIL)', () => {
		const text = 'Email john.doe@company.com or ping 192.168.1.1';
		const resolved = ConflictResolver.resolve([
			{
				type: 'EMAIL',
				start: 6,
				end: 26,
				source: 'REGEX',
				confidence: 1.0,
				redacted: true
			},
			{
				type: 'PER',
				start: 6,
				end: 14, // "john.doe" inside the email
				source: 'NER',
				confidence: 0.99,
				redacted: true
			},
			{
				type: 'IP',
				start: 35,
				end: 46,
				source: 'REGEX',
				confidence: 1.0,
				redacted: true
			},
			{
				type: 'ORG',
				start: 35,
				end: 46, // NER misclassifying IP as ORG
				source: 'NER',
				confidence: 0.85,
				redacted: true
			}
		]);

		expect(resolved).toHaveLength(2);
		expect(resolved[0].type).toBe('EMAIL');
		expect(resolved[1].type).toBe('IP');
		expect(applyRedactions(text, resolved)).toBe('Email [EMAIL] or ping [IP]');
	});

	it('prefers wider high-confidence (>0.80) NER span over narrower span', () => {
		const resolved = ConflictResolver.resolve([
			{
				type: 'ORG',
				start: 0,
				end: 4, // "Acme"
				source: 'NER',
				confidence: 0.75,
				redacted: true
			},
			{
				type: 'ORG',
				start: 0,
				end: 16, // "Acme Corp Global"
				source: 'NER',
				confidence: 0.91,
				redacted: true
			}
		]);

		expect(resolved).toHaveLength(1);
		expect(resolved[0].end).toBe(16);
	});
});

describe('Int32Array Buffer Transfer, Verification & Viewport Virtualization', () => {
	it('round-trips entities through flat Int32Array buffer', () => {
		const original = [
			{
				type: 'PER' as const,
				start: 5,
				end: 15,
				source: 'NER' as const,
				confidence: 0.9421,
				redacted: true
			},
			{
				type: 'AMBIGUOUS_ORG' as const,
				start: 20,
				end: 25,
				source: 'NER' as const,
				confidence: 0.55,
				ambiguous: true,
				redacted: false
			}
		];

		const buffer = encodeEntitiesToBuffer(original);
		const decoded = decodeEntitiesFromBuffer(buffer);
		expect(decoded).toEqual(original);
	});

	it('flags residual SSN patterns during Masked Redaction Verification', () => {
		const unsafeResult = verifySanitizedText('User [NAME] has SSN 123-45-6789 on file.');
		expect(unsafeResult.valid).toBe(false);
		expect(unsafeResult.warnings).toContain('Potential unmasked SSN detected.');

		const safeResult = verifySanitizedText('User [NAME] logged in from [IP].');
		expect(safeResult.valid).toBe(true);
		expect(safeResult.warnings).toHaveLength(0);
	});

	it('slices highlight spans only within active viewport + 200px buffer', () => {
		const lines = Array.from({ length: 100 }, (_, i) => `Line ${i}: user${i}@example.com`);
		const text = lines.join('\n');
		const entities = RegexEngine.scan(text);

		// At top of scroll (scrollTop = 0, height = 100px, buffer = 200px => ~15 lines)
		const range = getViewportCharRange(text, 0, 100, 20, 200);
		const segments = buildHighlightSegments(text, entities, range);
		const highlightedSpans = segments.filter((s) => Boolean(s.entity));

		expect(highlightedSpans.length).toBeGreaterThan(0);
		expect(highlightedSpans.length).toBeLessThan(entities.length);
	});

	it('unwraps Proxy-wrapped config arrays in WorkerManager so postMessage structuredClone succeeds', async () => {
		const { WorkerManager } = await import('./WorkerManager');
		const proxiedTypes = new Proxy(['PER', 'ORG', 'EMAIL'] as const, {});
		let clonedSuccessfully = false;

		const manager = new WorkerManager();
		// Attach a mock worker that uses native structuredClone just like browser postMessage
		(manager as unknown as { worker: { postMessage: (msg: unknown) => void } }).worker = {
			postMessage(msg: unknown) {
				const cloned = structuredClone(msg) as { jobId: number };
				clonedSuccessfully = true;
				(
					manager as unknown as {
						activeResolvers: Map<number, { resolve: (v: unknown) => void }>;
					}
				).activeResolvers
					.get(cloned.jobId)
					?.resolve({
						type: 'SCAN_SUCCESS',
						jobId: cloned.jobId,
						entities: []
					});
			}
		};

		await manager.scan('test@example.com', {
			aggressiveMode: false,
			enabledTypes: proxiedTypes as unknown as Array<'PER' | 'ORG' | 'EMAIL'>
		});

		expect(clonedSuccessfully).toBe(true);
	});
});
