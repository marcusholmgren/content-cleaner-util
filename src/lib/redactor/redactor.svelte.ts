import { CustomRuleStore } from './CustomRuleStore.svelte';
import {
	DEFAULT_ENABLED_TYPES,
	applyRedactions,
	verifySanitizedText,
	type VerificationResult
} from './Engine';
import { WorkerManager } from './WorkerManager';
import type { CustomRule, EntityType, RedactionEntity, RuntimeDevice } from './types';

export class RedactorState {
	rawText = $state('');
	isProcessing = $state(false);
	entities = $state<RedactionEntity[]>([]);
	aggressiveMode = $state(false);
	enabledTypes = $state<EntityType[]>([...DEFAULT_ENABLED_TYPES]);
	runtimeDevice = $state<RuntimeDevice>('regex-only');
	lastDurationMs = $state<number | null>(null);
	verificationWarnings = $state<string[]>([]);
	errorMessage = $state<string | null>(null);

	workerManager: WorkerManager;
	customRuleStore: CustomRuleStore;
	private timeoutId: ReturnType<typeof setTimeout> | null = null;
	private lastJobId = -1;
	private latestInputSeq = 0;
	private unsubscribeDevice?: () => void;

	constructor(workerManager?: WorkerManager) {
		this.workerManager = workerManager ?? new WorkerManager();
		this.runtimeDevice = this.workerManager.runtimeDevice;
		this.unsubscribeDevice = this.workerManager.onDeviceChange((device) => {
			this.runtimeDevice = device;
		});
		this.customRuleStore = new CustomRuleStore(this.workerManager, () => {
			if (this.rawText.trim().length > 0) {
				this.handleInput(this.rawText);
			}
		});
	}

	sanitizedText = $derived.by(() => {
		return applyRedactions(this.rawText, this.entities);
	});

	statusText = $derived.by(() => {
		if (this.isProcessing) {
			return 'Processing...';
		}
		if (this.lastDurationMs === null) {
			if (this.runtimeDevice === 'webgpu') return 'WebGPU Active';
			if (this.runtimeDevice === 'wasm') return 'WASM Fallback';
			return 'Idle';
		}
		const ms = `${this.lastDurationMs}ms`;
		if (this.runtimeDevice === 'webgpu') {
			return `WebGPU Active (${ms})`;
		}
		if (this.runtimeDevice === 'wasm') {
			return `WASM Fallback (${ms})`;
		}
		return `Regex Engine (${ms})`;
	});

	async init() {
		await this.customRuleStore.loadCustomRules();
	}

	handleInput(text: string) {
		this.rawText = text;
		this.verificationWarnings = [];
		this.errorMessage = null;
		const seq = ++this.latestInputSeq;

		if (this.timeoutId) {
			clearTimeout(this.timeoutId);
			this.timeoutId = null;
		}

		if (!text || text.trim().length === 0) {
			this.entities = [];
			this.isProcessing = false;
			this.lastDurationMs = null;
			return;
		}

		this.isProcessing = true;

		this.timeoutId = setTimeout(async () => {
			await this.runScan(text, seq);
		}, 120);
	}

	private async runScan(text: string, seq: number) {
		try {
			const result = await this.workerManager.scan(text, {
				aggressiveMode: Boolean(this.aggressiveMode),
				enabledTypes: $state.snapshot(this.enabledTypes)
			});

			// Drop stale responses if newer input has already arrived or resolved
			if (seq !== this.latestInputSeq) {
				return;
			}

			if (result.jobId >= this.lastJobId) {
				this.lastJobId = result.jobId;
				this.entities = result.entities ?? [];
				if (result.runtimeDevice) {
					this.runtimeDevice = result.runtimeDevice;
				}
				if (typeof result.durationMs === 'number') {
					this.lastDurationMs = result.durationMs;
				}
			}
		} catch (error) {
			if (seq === this.latestInputSeq) {
				this.errorMessage = error instanceof Error ? error.message : 'Scanning failed';
				console.error('Scanning failed', error);
			}
		} finally {
			if (seq === this.latestInputSeq) {
				this.isProcessing = false;
			}
		}
	}

	toggleEntityRedaction(index: number) {
		if (index < 0 || index >= this.entities.length) return;
		this.entities = this.entities.map((entity, i) =>
			i === index ? { ...entity, redacted: entity.redacted === false } : entity
		);
	}

	setAggressiveMode(enabled: boolean) {
		this.aggressiveMode = enabled;
		if (this.rawText.trim().length > 0) {
			this.handleInput(this.rawText);
		}
	}

	toggleEntityType(type: EntityType) {
		const related: EntityType[] =
			type === 'PER'
				? ['PER', 'AMBIGUOUS_PER']
				: type === 'ORG'
					? ['ORG', 'AMBIGUOUS_ORG']
					: type === 'TOKEN'
						? ['TOKEN', 'SUSPECTED_TOKEN']
						: [type];

		const isCurrentlyEnabled = this.enabledTypes.includes(type);
		if (isCurrentlyEnabled) {
			this.enabledTypes = this.enabledTypes.filter((t) => !related.includes(t));
		} else {
			const additions = related.filter((t) => !this.enabledTypes.includes(t));
			this.enabledTypes = [...this.enabledTypes, ...additions];
		}

		if (this.rawText.trim().length > 0) {
			this.handleInput(this.rawText);
		}
	}

	async addCustomRule(rule: Omit<CustomRule, 'id' | 'createdAt'>) {
		return this.customRuleStore.addCustomRule(rule);
	}

	async updateCustomRule(id: string, updates: Partial<Omit<CustomRule, 'id' | 'createdAt'>>) {
		return this.customRuleStore.updateCustomRule(id, updates);
	}

	async removeCustomRule(id: string) {
		await this.customRuleStore.removeCustomRule(id);
	}

	async toggleCustomRule(id: string) {
		await this.customRuleStore.toggleRule(id);
	}

	async toggleCustomRuleCaseSensitivity(id: string) {
		await this.customRuleStore.toggleCaseSensitivity(id);
	}

	verifyBeforeCopy(): VerificationResult {
		const result = verifySanitizedText(this.sanitizedText);
		this.verificationWarnings = result.warnings;
		return result;
	}

	destroy() {
		if (this.timeoutId) {
			clearTimeout(this.timeoutId);
			this.timeoutId = null;
		}
		this.unsubscribeDevice?.();
		this.workerManager.destroy();
	}
}
