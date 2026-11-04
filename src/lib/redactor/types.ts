export type EntityType = 'PER' | 'ORG' | 'LOC' | 'EMAIL' | 'TOKEN' | 'IP' | 'CREDIT_CARD';

export interface ScanRequest {
	type: 'SCAN_PAYLOAD';
	jobId: number;
	text: string;
	config: {
		aggressiveMode: boolean;
		enabledTypes: EntityType[];
	};
}

export interface ScanResultPayload {
	type: 'SCAN_SUCCESS';
	jobId: number;
	entities: Array<{
		type: EntityType;
		start: number;
		end: number;
		source: 'REGEX' | 'NER';
		confidence: number;
	}>;
}

export interface WorkerErrorPayload {
	type: 'SCAN_ERROR';
	jobId: number;
	error: string;
}

export type WorkerMessage = ScanRequest;
export type HostMessage = ScanResultPayload | WorkerErrorPayload | { type: 'MODEL_READY' };
