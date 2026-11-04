import { WorkerManager } from './WorkerManager';
import type { ScanResultPayload } from './types';

export class RedactorState {
	rawText = $state('');
	isProcessing = $state(false);
	entities = $state<ScanResultPayload['entities']>([]);
	workerManager: WorkerManager;
	private timeoutId: NodeJS.Timeout | null = null;
	private lastJobId = -1;

	constructor() {
		this.workerManager = new WorkerManager();
	}

	sanitizedText = $derived.by(() => {
		return this.applyRedactions(this.rawText, this.entities);
	});

	private applyRedactions(text: string, entities: ScanResultPayload['entities']) {
		if (!entities.length) return text;

		let result = '';
		let lastIndex = 0;

		for (const entity of entities) {
			if (entity.start < lastIndex) continue;

			result += text.slice(lastIndex, entity.start);
			result += `[${entity.type}]`;
			lastIndex = entity.end;
		}
		result += text.slice(lastIndex);

		return result;
	}

	handleInput(text: string) {
		this.rawText = text;
		this.isProcessing = true;

		if (this.timeoutId) {
			clearTimeout(this.timeoutId);
		}

		this.timeoutId = setTimeout(async () => {
			try {
				const result = await this.workerManager.scan(text);
				if (result.jobId > this.lastJobId) {
					this.lastJobId = result.jobId;
					this.entities = result.entities;
				}
			} catch (error) {
				console.error('Scanning failed', error);
			} finally {
				this.isProcessing = false;
			}
		}, 120);
	}
}
