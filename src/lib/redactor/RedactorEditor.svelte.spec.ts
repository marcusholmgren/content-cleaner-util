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
});
