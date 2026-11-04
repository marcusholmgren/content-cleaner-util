export type EntityType =
	| 'PER'
	| 'ORG'
	| 'LOC'
	| 'EMAIL'
	| 'TOKEN'
	| 'IP'
	| 'CREDIT_CARD'
	| 'SUSPECTED_TOKEN'
	| 'AMBIGUOUS_PER'
	| 'AMBIGUOUS_ORG'
	| 'CUSTOM_RULE';

export type CustomRuleType = 'EXACT' | 'PHRASE' | 'REGEX';

export interface CustomRule {
	id: string;
	type: CustomRuleType;
	value: string;
	caseSensitive: boolean;
	enabled: boolean;
	createdAt: number;
}

export interface CompiledCustomRule {
	id: string;
	type: CustomRuleType;
	value: string;
	caseSensitive: boolean;
	matcher: string | RegExp;
}

export interface SyncCustomRulesPayload {
	type: 'SYNC_CUSTOM_RULES';
	rules: CustomRule[];
}

export type RuntimeDevice = 'webgpu' | 'wasm' | 'regex-only';

export interface RedactionEntity {
	type: EntityType;
	start: number;
	end: number;
	source: 'REGEX' | 'CUSTOM' | 'NER';
	confidence: number;
	ambiguous?: boolean;
	redacted?: boolean;
	ruleId?: string;
	ruleValue?: string;
}

export interface ScanConfig {
	aggressiveMode: boolean;
	enabledTypes: EntityType[];
}

export interface ScanRequest {
	type: 'SCAN_PAYLOAD';
	jobId: number;
	text: string;
	config: ScanConfig;
}

export interface ScanResultPayload {
	type: 'SCAN_SUCCESS';
	jobId: number;
	entities: RedactionEntity[];
	buffer?: Int32Array;
	runtimeDevice?: RuntimeDevice;
	durationMs?: number;
}

export interface WorkerErrorPayload {
	type: 'SCAN_ERROR';
	jobId: number;
	error: string;
}

export interface ModelReadyPayload {
	type: 'MODEL_READY';
	device: RuntimeDevice;
}

export type WorkerMessage = ScanRequest | SyncCustomRulesPayload;
export type HostMessage = ScanResultPayload | WorkerErrorPayload | ModelReadyPayload;
