import { page } from 'vitest/browser';
import { describe, expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import RedactorEditor from './RedactorEditor.svelte';

describe('RedactorEditor.svelte Custom Dictionary UI', () => {
	it('allows a user to add and remove custom redaction phrases', async () => {
		render(RedactorEditor);

		await expect
			.element(page.getByRole('heading', { name: 'Custom Redaction Dictionary' }))
			.toBeInTheDocument();

		const phraseInput = page.getByLabelText('Custom Phrase or Pattern');
		await phraseInput.fill('Project Titan');

		const addButton = page.getByTestId('add-custom-rule-btn');
		await addButton.click();

		// The new phrase appears in the custom dictionary table
		await expect.element(page.getByText('Project Titan')).toBeInTheDocument();

		// Remove the custom phrase
		const removeButton = page.getByTestId('remove-custom-rule-btn');
		await removeButton.click();

		await expect.element(page.getByTestId('empty-custom-rules')).toBeInTheDocument();
	});

	it('disables Copy Redacted while scan is in progress and enables it after completion', async () => {
		render(RedactorEditor);

		const copyBtn = page.getByRole('button', { name: 'Copy Redacted' });
		// Initially empty text, copy should be disabled
		await expect.element(copyBtn).toBeDisabled();

		const textarea = page.getByPlaceholder('Paste your text here...');
		await textarea.fill('John Doe at Apple');

		// Wait for scan completion
		await expect.element(copyBtn).toBeEnabled();
	});

	it('fails safe when verifyBeforeCopy reports a warning, requiring explicit override', async () => {
		render(RedactorEditor);

		let copiedText = '';
		Object.defineProperty(navigator, 'clipboard', {
			value: {
				writeText: async (text: string) => {
					copiedText = text;
				}
			},
			configurable: true,
			writable: true
		});

		const textarea = page.getByPlaceholder('Paste your text here...');
		// Text containing unmasked SSN which triggers verifySanitizedText warning
		await textarea.fill('My SSN is 123-45-6789.');

		const copyBtn = page.getByRole('button', { name: /Copy Redacted|Copied!/ });
		await expect.element(copyBtn).toBeEnabled();

		// Click Copy Redacted
		await copyBtn.click();

		// Warning banner should appear with warning message and explicit override button
		const warningBanner = page.getByTestId('verification-warning');
		await expect.element(warningBanner).toBeInTheDocument();
		await expect.element(page.getByText('Potential unmasked SSN detected.')).toBeInTheDocument();

		// Fail safe: copiedText should NOT be set, and button should NOT show 'Copied!'
		expect(copiedText).toBe('');
		await expect.element(copyBtn).toHaveTextContent('Copy Redacted');

		// Click the explicit override button
		const overrideBtn = page.getByTestId('copy-override-btn');
		await expect.element(overrideBtn).toBeInTheDocument();
		await overrideBtn.click();

		// Should have copied with override
		expect(copiedText).toBe('My SSN is 123-45-6789.');
		await expect.element(copyBtn).toHaveTextContent('Copied!');
		await expect.element(page.getByTestId('copy-disclaimer-toast')).toBeInTheDocument();
	});

	it('detects Swedish SSN, renders Verification Status Panel, and highlights SSN span on badge hover', async () => {
		render(RedactorEditor);

		const textarea = page.getByPlaceholder('Paste your text here...');
		await textarea.fill('Personal ID: 811218-9876');

		const statusPanel = page.getByTestId('verification-status-panel');
		await expect.element(statusPanel).toBeInTheDocument();

		const badge = page.getByTestId('verification-report-badge');
		await expect.element(badge).toHaveTextContent('SSN Pattern Detected - 1 Masked');

		const sanitizedPreview = page.getByTestId('sanitized-preview');
		await expect.element(sanitizedPreview).toHaveTextContent('Personal ID: [SSN]');

		// Hovering over the verification badge highlights the SSN span in the twin-layer overlay
		await badge.hover();
		const highlightSpan = page.getByTestId('highlight-layer').getByText('811218-9876');
		await expect.element(highlightSpan).toHaveAttribute('data-verification-highlighted', 'true');
	});
});
