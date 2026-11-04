import type { ScanRequest, ScanResultPayload } from './types';

export class WorkerManager {
	private worker: Worker | null = null;
	private currentJobId = 0;
	private activeResolvers = new Map<number, (res: ScanResultPayload) => void>();

	constructor() {
		// Only instantiate worker in browser environment
		if (typeof window !== 'undefined') {
			this.worker = new Worker(new URL('./workers/redactor.worker.ts', import.meta.url), {
				type: 'module'
			});

			this.worker.onmessage = (event: MessageEvent<ScanResultPayload>) => {
				const { jobId } = event.data;
				const resolver = this.activeResolvers.get(jobId);
				if (resolver) {
					resolver(event.data);
					this.activeResolvers.delete(jobId);
				}
			};
		}
	}

	public async scan(text: string): Promise<ScanResultPayload> {
		if (!this.worker) {
			return { type: 'SCAN_SUCCESS', jobId: -1, entities: [] };
		}
		const jobId = ++this.currentJobId;
		return new Promise((resolve) => {
			this.activeResolvers.set(jobId, resolve);
			this.worker!.postMessage({
				type: 'SCAN_PAYLOAD',
				jobId,
				text,
				config: { aggressiveMode: false, enabledTypes: ['PER', 'ORG', 'IP', 'EMAIL'] }
			} satisfies ScanRequest);
		});
	}
}
