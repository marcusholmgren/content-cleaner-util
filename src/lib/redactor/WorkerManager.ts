import { DEFAULT_ENABLED_TYPES, RegexEngine, decodeEntitiesFromBuffer } from './Engine';
import type {
	HostMessage,
	RuntimeDevice,
	ScanConfig,
	ScanRequest,
	ScanResultPayload
} from './types';

interface PendingJob {
	resolve: (res: ScanResultPayload) => void;
	reject: (err: Error) => void;
}

export class WorkerManager {
	private worker: Worker | null = null;
	private currentJobId = 0;
	private activeResolvers = new Map<number, PendingJob>();
	public runtimeDevice: RuntimeDevice = 'regex-only';
	private deviceListeners = new Set<(device: RuntimeDevice) => void>();

	constructor() {
		if (typeof window !== 'undefined' && typeof Worker !== 'undefined') {
			this.worker = new Worker(new URL('./workers/redactor.worker.ts', import.meta.url), {
				type: 'module'
			});

			this.worker.onmessage = (event: MessageEvent<HostMessage>) => {
				const data = event.data;
				if (!data) return;

				if (data.type === 'MODEL_READY') {
					this.runtimeDevice = data.device;
					for (const listener of this.deviceListeners) {
						listener(data.device);
					}
					return;
				}

				const pending = this.activeResolvers.get(data.jobId);
				if (!pending) return;
				this.activeResolvers.delete(data.jobId);

				if (data.type === 'SCAN_ERROR') {
					pending.reject(new Error(data.error));
					return;
				}

				if (data.type === 'SCAN_SUCCESS') {
					if (data.runtimeDevice) {
						this.runtimeDevice = data.runtimeDevice;
						for (const listener of this.deviceListeners) {
							listener(data.runtimeDevice);
						}
					}

					const entities =
						Array.isArray(data.entities) && data.entities.length > 0
							? data.entities
							: data.buffer instanceof Int32Array && data.buffer.length > 0
								? decodeEntitiesFromBuffer(data.buffer)
								: [];

					pending.resolve({
						...data,
						entities
					});
				}
			};

			this.worker.onerror = (event: ErrorEvent) => {
				const err = new Error(event.message || 'Worker execution error');
				for (const [, pending] of this.activeResolvers) {
					pending.reject(err);
				}
				this.activeResolvers.clear();
			};
		}
	}

	public onDeviceChange(cb: (device: RuntimeDevice) => void): () => void {
		this.deviceListeners.add(cb);
		return () => {
			this.deviceListeners.delete(cb);
		};
	}

	public async scan(text: string, config?: Partial<ScanConfig>): Promise<ScanResultPayload> {
		const jobId = ++this.currentJobId;
		const resolvedConfig: ScanConfig = {
			aggressiveMode: Boolean(config?.aggressiveMode ?? false),
			enabledTypes: config?.enabledTypes ? [...config.enabledTypes] : [...DEFAULT_ENABLED_TYPES]
		};

		if (!this.worker) {
			const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
			const entities = RegexEngine.scan(text, resolvedConfig);
			const durationMs = Math.max(
				0,
				Math.round(
					(typeof performance !== 'undefined' ? performance.now() : Date.now()) - startTime
				)
			);
			return {
				type: 'SCAN_SUCCESS',
				jobId,
				entities,
				runtimeDevice: 'regex-only',
				durationMs
			};
		}

		return new Promise<ScanResultPayload>((resolve, reject) => {
			this.activeResolvers.set(jobId, { resolve, reject });
			this.worker!.postMessage({
				type: 'SCAN_PAYLOAD',
				jobId,
				text,
				config: resolvedConfig
			} satisfies ScanRequest);
		});
	}

	public destroy(): void {
		if (this.worker) {
			this.worker.terminate();
			this.worker = null;
		}
		this.activeResolvers.clear();
		this.deviceListeners.clear();
	}
}
