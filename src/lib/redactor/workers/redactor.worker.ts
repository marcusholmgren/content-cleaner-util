import { pipeline, env } from '@huggingface/transformers';
import type { ScanRequest, ScanResultPayload } from '../types';

// Force browser execution constraints
env.allowLocalModels = false;
env.useBrowserCache = true;

let classifierPromise: Promise<unknown> | null = null;

async function getClassifier() {
	if (!classifierPromise) {
		classifierPromise = pipeline('token-classification', 'Xenova/rubert-tiny-ner', {
			device: 'webgpu' // Auto-falls back to wasm if WebGPU is unavailable
		});
	}
	return classifierPromise;
}

const REGEX_RULES = [
	{ type: 'EMAIL' as const, rule: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/g },
	{ type: 'IP' as const, rule: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g },
	{ type: 'TOKEN' as const, rule: /\b(?:ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48})\b/g }
];

self.onmessage = async (e: MessageEvent<ScanRequest>) => {
	const { jobId, text } = e.data;
	const entities: ScanResultPayload['entities'] = [];

	// 1. Synchronous Regex Pass
	for (const { type, rule } of REGEX_RULES) {
		let match: RegExpExecArray | null;
		while ((match = rule.exec(text)) !== null) {
			entities.push({
				type,
				start: match.index,
				end: match.index + match[0].length,
				source: 'REGEX',
				confidence: 1.0
			});
		}
	}

	// 2. Transformer Inference Pass
	try {
		const classifier = await getClassifier();
		const rawTokens: Array<{ entity: string; start: number; end: number; score: number }> = await (
			classifier as (
				...args: unknown[]
			) => Promise<Array<{ entity: string; start: number; end: number; score: number }>>
		)(text, {
			ignore_labels: ['O']
		});

		for (const token of rawTokens) {
			const type = token.entity.replace(/^[BI]-/, '') as 'PER' | 'ORG';
			// Basic collision skip if regex already handled the range
			const overlaps = entities.some((e) => token.start >= e.start && token.end <= e.end);
			if (!overlaps) {
				entities.push({
					type,
					start: token.start,
					end: token.end,
					source: 'NER',
					confidence: token.score
				});
			}
		}
	} catch (err) {
		console.error('NER Inference failed, returning regex results only', err);
	}

	self.postMessage({
		type: 'SCAN_SUCCESS',
		jobId,
		entities: entities.sort((a, b) => a.start - b.start)
	} satisfies ScanResultPayload);
};
