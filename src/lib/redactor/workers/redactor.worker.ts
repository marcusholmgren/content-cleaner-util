import { pipeline, env } from '@huggingface/transformers';
import {
	RegexEngine,
	CustomRuleEngine,
	ConflictResolver,
	createZeroMaskedBuffer,
	splitIntoChunks,
	shouldSkipChunk,
	alignAndNormalizeNerTokens,
	encodeEntitiesToBuffer,
	type RawNerToken
} from '../Engine';
import type {
	HostMessage,
	RedactionEntity,
	RuntimeDevice,
	ScanResultPayload,
	WorkerMessage
} from '../types';

// Force browser execution constraints
env.allowLocalModels = false;
env.useBrowserCache = true;

type ClassifierFn = (
	text: string,
	options?: { ignore_labels?: string[] }
) => Promise<RawNerToken[]>;

let classifierPromise: Promise<ClassifierFn> | null = null;
let activeDevice: RuntimeDevice = 'regex-only';
const customRuleEngine = new CustomRuleEngine();

const DEFAULT_MODEL_ID = 'Xenova/bert-base-NER';

/**
 * Probe whether WebGPU is genuinely usable (adapter + device can be acquired).
 * Note: Checking `'gpu' in navigator` alone is insufficient in Chrome on Linux/Windows
 * without WebGPU enabled, where `navigator.gpu` exists but `requestAdapter()` returns `null`.
 * Calling `pipeline(..., { device: 'webgpu' })` when `requestAdapter()` returns `null`
 * permanently rejects Transformers.js's internal `webInitChain` promise, breaking WASM fallback.
 */
async function isWebGpuFunctional(): Promise<boolean> {
	try {
		if (typeof navigator === 'undefined' || !('gpu' in navigator) || !navigator.gpu) {
			return false;
		}
		const gpu = navigator.gpu as {
			requestAdapter?: () => Promise<{
				requestDevice?: () => Promise<{ destroy?: () => void } | null>;
			} | null>;
		};
		if (typeof gpu.requestAdapter !== 'function') {
			return false;
		}
		const adapter = await gpu.requestAdapter();
		if (!adapter || typeof adapter.requestDevice !== 'function') {
			return false;
		}
		const device = await adapter.requestDevice();
		if (!device) {
			return false;
		}
		device.destroy?.();
		return true;
	} catch {
		return false;
	}
}

async function initClassifier(): Promise<ClassifierFn> {
	const useWebGpu = await isWebGpuFunctional();
	const device: 'webgpu' | 'wasm' = useWebGpu ? 'webgpu' : 'wasm';

	try {
		const instance = await pipeline('token-classification', DEFAULT_MODEL_ID, {
			device,
			dtype: 'q8'
		});
		activeDevice = device;
		self.postMessage({
			type: 'MODEL_READY',
			device
		} satisfies HostMessage);
		return instance as unknown as ClassifierFn;
	} catch (err) {
		classifierPromise = null;
		throw err;
	}
}

async function getClassifier(): Promise<ClassifierFn> {
	if (!classifierPromise) {
		classifierPromise = initClassifier();
	}
	return classifierPromise;
}

self.onmessage = async (e: MessageEvent<WorkerMessage>) => {
	const data = e.data;
	if (!data) return;

	if (data.type === 'SYNC_CUSTOM_RULES') {
		customRuleEngine.compile(Array.isArray(data.rules) ? data.rules : []);
		return;
	}

	if (data.type !== 'SCAN_PAYLOAD') return;

	const { jobId, text, config } = data;
	const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();

	try {
		if (!text || text.trim().length === 0) {
			const emptyBuffer = new Int32Array(0);
			self.postMessage(
				{
					type: 'SCAN_SUCCESS',
					jobId,
					entities: [],
					buffer: emptyBuffer,
					runtimeDevice: activeDevice,
					durationMs: 0
				} satisfies ScanResultPayload,
				{ transfer: [emptyBuffer.buffer] }
			);
			return;
		}

		// Stage 1a: Synchronous Deterministic Regex & High-Entropy Pass
		const regexStartTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
		const regexEntities = RegexEngine.scan(text, config);
		const regexDuration =
			(typeof performance !== 'undefined' ? performance.now() : Date.now()) - regexStartTime;

		const ssnMatches = regexEntities.filter((e) => e.type === 'SSN');
		const verificationReports = [
			{
				ruleId: 'swedish-ssn-check',
				status: ssnMatches.length > 0 ? 'DETECTED' : 'NOT_DETECTED',
				matchesCount: ssnMatches.length,
				executionTimeMs: Math.round(regexDuration),
				message:
					ssnMatches.length > 0
						? `SSN Pattern Detected - ${ssnMatches.length} Masked`
						: 'SSN Pattern Checked - 0 Found'
			}
		] as const;

		// Stage 1b: User Custom Rules (Aho-Corasick + Pre-compiled SafeRegex)
		const customEntities = customRuleEngine.scan(text, config);

		const nerEntities: RedactionEntity[] = [];

		const enabledTypes = config?.enabledTypes ?? [];
		const nerRequested =
			enabledTypes.length === 0 ||
			enabledTypes.some((t) => ['PER', 'ORG', 'LOC', 'AMBIGUOUS_PER', 'AMBIGUOUS_ORG'].includes(t));

		// Stage 2: Probabilistic NER Pass with Zero-Masking (skips both Regex and Custom Rule spans)
		if (nerRequested) {
			const zeroMaskedText = createZeroMaskedBuffer(text, [...regexEntities, ...customEntities]);
			const chunks = splitIntoChunks(zeroMaskedText, 384, 64);
			const eligibleChunks = chunks.filter((chunk) => !shouldSkipChunk(chunk.text));

			if (eligibleChunks.length > 0) {
				try {
					const classifier = await getClassifier();
					for (const chunk of eligibleChunks) {
						const rawTokens = await classifier(chunk.text, {
							ignore_labels: ['O']
						});
						const aligned = alignAndNormalizeNerTokens(
							Array.isArray(rawTokens) ? rawTokens : [],
							chunk.text,
							chunk.startOffset,
							text,
							config
						);
						nerEntities.push(...aligned);
					}
				} catch (err) {
					activeDevice = 'regex-only';
					console.error('NER Inference failed, returning regex results only', err);
				}
			}
		}

		// Stage 3: Conflict Resolution and Boundary Clamping (REGEX > CUSTOM > NER)
		const resolvedEntities = ConflictResolver.resolve([
			...regexEntities,
			...customEntities,
			...nerEntities
		]);
		const buffer = encodeEntitiesToBuffer(resolvedEntities);
		const durationMs = Math.max(
			0,
			Math.round((typeof performance !== 'undefined' ? performance.now() : Date.now()) - startTime)
		);

		self.postMessage(
			{
				type: 'SCAN_SUCCESS',
				jobId,
				entities: resolvedEntities,
				verificationReports: [...verificationReports],
				buffer,
				runtimeDevice: activeDevice,
				durationMs
			} satisfies ScanResultPayload,
			{ transfer: [buffer.buffer] }
		);
	} catch (err) {
		self.postMessage({
			type: 'SCAN_ERROR',
			jobId,
			error: err instanceof Error ? err.message : String(err)
		} satisfies HostMessage);
	}
};
