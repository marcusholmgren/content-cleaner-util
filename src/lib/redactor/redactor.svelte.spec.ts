import { afterEach, describe, expect, it, vi } from 'vitest';
import { RedactorState } from './redactor.svelte';
import { WorkerManager } from './WorkerManager';

describe('RedactorState copy safety', () => {
	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	it('keeps copying disabled when the latest scan fails', async () => {
		vi.useFakeTimers();
		const workerManager = new WorkerManager();
		vi.spyOn(workerManager, 'scan').mockRejectedValue(new Error('Worker failed'));
		vi.spyOn(console, 'error').mockImplementation(() => {});

		const state = new RedactorState(workerManager);
		state.handleInput('New text with unrecognized PII');

		await vi.advanceTimersByTimeAsync(120);

		expect(state.isProcessing).toBe(false);
		expect(state.isScanStale).toBe(true);
		expect(state.canCopy).toBe(false);
		expect(state.verifyBeforeCopy().valid).toBe(false);

		state.destroy();
	});

	it('populates verificationReports and redacts Swedish SSNs by default', async () => {
		vi.useFakeTimers();
		const workerManager = new WorkerManager();
		// Force synchronous regex fallback path for deterministic testing
		workerManager.worker?.terminate();
		workerManager.worker = null;

		const state = new RedactorState(workerManager);
		state.handleInput('Applicant SSN: 811218-9876');

		await vi.advanceTimersByTimeAsync(120);

		expect(state.sanitizedText).toBe('Applicant SSN: [SSN]');
		expect(state.verificationReports).toHaveLength(1);
		expect(state.verificationReports[0]).toMatchObject({
			ruleId: 'swedish-ssn-check',
			status: 'DETECTED',
			matchesCount: 1,
			message: 'SSN Pattern Detected - 1 Masked'
		});

		state.handleInput('');
		expect(state.verificationReports).toEqual([]);

		state.destroy();
	});
});
