import {
	ConflictResolver,
	CustomRuleEngine,
	DEFAULT_ENABLED_TYPES,
	RegexEngine,
	decodeEntitiesFromBuffer
} from './Engine';
import type {
	CustomRule,
	HostMessage,
	RuntimeDevice,
	ScanConfig,
	ScanRequest,
	ScanResultPayload,
	SyncCustomRulesPayload
} from './types';

interface PendingJob {
	resolve: (res: ScanResultPayload) => void;
	reject: (err: Error) => void;
}

export class WorkerManager {
	public worker: Worker | null = null;
	private currentJobId = 0;
	private activeResolvers = new Map<number, PendingJob>();
	public runtimeDevice: RuntimeDevice = 'regex-only';
	private deviceListeners = new Set<(device: RuntimeDevice) => void>();
	private fallbackCustomEngine = new CustomRuleEngine();
	private latestCustomRules: CustomRule[] = [];

	constructor() {
		if (typeof window !== 'undefined' && typeof Worker !== 'undefined') {
			this.initWorker();
		}
	}

	private initWorker() {
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

		if (this.latestCustomRules.length > 0) {
			this.worker.postMessage({
				type: 'SYNC_CUSTOM_RULES',
				rules: this.latestCustomRules
			} satisfies SyncCustomRulesPayload);
		}
	}

	public syncCustomRules(rules: CustomRule[]): void {
		const plainRules = rules.map((r) => ({
			id: String(r.id),
			type: r.type,
			value: String(r.value),
			caseSensitive: Boolean(r.caseSensitive),
			enabled: Boolean(r.enabled),
			createdAt: Number(r.createdAt)
		}));
		this.latestCustomRules = plainRules;
		this.fallbackCustomEngine.compile(plainRules);

		if (this.worker) {
			this.worker.postMessage({
				type: 'SYNC_CUSTOM_RULES',
				rules: plainRules
			} satisfies SyncCustomRulesPayload);
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
			const regexEntities = RegexEngine.scan(text, resolvedConfig);
			const customEntities = this.fallbackCustomEngine.scan(text, resolvedConfig);
			const entities = ConflictResolver.resolve([...regexEntities, ...customEntities]);
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
