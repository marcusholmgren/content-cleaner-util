import { get, set } from 'idb-keyval';
import { validateCustomRule, type RuleValidationResult } from './Engine';
import type { WorkerManager } from './WorkerManager';
import type { CustomRule, CustomRuleType } from './types';

const STORAGE_KEY = 'customRules';

function isIndexedDbAvailable(): boolean {
	return typeof window !== 'undefined' && typeof indexedDB !== 'undefined';
}

function generateId(): string {
	if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
		return crypto.randomUUID();
	}
	return `rule-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

export class CustomRuleStore {
	rules = $state<CustomRule[]>([]);
	private workerManager: WorkerManager;
	private onRulesChanged?: () => void;

	constructor(workerManager: WorkerManager, onRulesChanged?: () => void) {
		this.workerManager = workerManager;
		this.onRulesChanged = onRulesChanged;
	}

	private async persist(): Promise<void> {
		if (!isIndexedDbAvailable()) return;
		try {
			await set(STORAGE_KEY, $state.snapshot(this.rules));
		} catch (err) {
			console.warn('Failed to persist custom rules to IndexedDB', err);
		}
	}

	async loadCustomRules(): Promise<void> {
		if (isIndexedDbAvailable()) {
			try {
				const loaded = await get<CustomRule[]>(STORAGE_KEY);
				if (Array.isArray(loaded)) {
					this.rules = loaded;
				}
			} catch (err) {
				console.warn('Failed to load custom rules from IndexedDB', err);
			}
		}
		this.syncToWorker();
	}

	validate(type: CustomRuleType, value: string): RuleValidationResult {
		return validateCustomRule(type, value);
	}

	async addCustomRule(
		rule: Omit<CustomRule, 'id' | 'createdAt'>
	): Promise<{ ok: boolean; error?: string; rule?: CustomRule }> {
		const trimmedValue = rule.value.trim();
		const validation = validateCustomRule(rule.type, trimmedValue);
		if (!validation.valid) {
			return { ok: false, error: validation.error };
		}

		// Prevent exact duplicate rules (same type, value, and case sensitivity)
		const duplicate = this.rules.some(
			(r) =>
				r.type === rule.type &&
				r.caseSensitive === rule.caseSensitive &&
				(r.caseSensitive
					? r.value === trimmedValue
					: r.value.toLowerCase() === trimmedValue.toLowerCase())
		);
		if (duplicate) {
			return { ok: false, error: 'This custom rule already exists.' };
		}

		const newRule: CustomRule = {
			...rule,
			value: trimmedValue,
			id: generateId(),
			createdAt: Date.now()
		};

		this.rules = [...this.rules, newRule];
		await this.persist();
		this.syncToWorker();
		return { ok: true, rule: newRule };
	}

	async updateCustomRule(
		id: string,
		updates: Partial<Omit<CustomRule, 'id' | 'createdAt'>>
	): Promise<{ ok: boolean; error?: string }> {
		const idx = this.rules.findIndex((r) => r.id === id);
		if (idx === -1) {
			return { ok: false, error: 'Rule not found.' };
		}

		const current = this.rules[idx];
		const nextType = updates.type ?? current.type;
		const nextValue = (updates.value ?? current.value).trim();

		const validation = validateCustomRule(nextType, nextValue);
		if (!validation.valid) {
			return { ok: false, error: validation.error };
		}

		const updatedRule: CustomRule = {
			...current,
			...updates,
			type: nextType,
			value: nextValue
		};

		this.rules = this.rules.map((r, i) => (i === idx ? updatedRule : r));
		await this.persist();
		this.syncToWorker();
		return { ok: true };
	}

	async removeCustomRule(id: string): Promise<void> {
		this.rules = this.rules.filter((r) => r.id !== id);
		await this.persist();
		this.syncToWorker();
	}

	async toggleRule(id: string): Promise<void> {
		const idx = this.rules.findIndex((r) => r.id === id);
		if (idx > -1) {
			this.rules = this.rules.map((r, i) => (i === idx ? { ...r, enabled: !r.enabled } : r));
			await this.persist();
			this.syncToWorker();
		}
	}

	async toggleCaseSensitivity(id: string): Promise<void> {
		const idx = this.rules.findIndex((r) => r.id === id);
		if (idx > -1) {
			this.rules = this.rules.map((r, i) =>
				i === idx ? { ...r, caseSensitive: !r.caseSensitive } : r
			);
			await this.persist();
			this.syncToWorker();
		}
	}

	syncToWorker(): void {
		const enabledSnapshot = $state
			.snapshot(this.rules)
			.filter((r) => r.enabled)
			.map((r) => ({ ...r }));
		this.workerManager.syncCustomRules(enabledSnapshot);
		this.onRulesChanged?.();
	}
}
