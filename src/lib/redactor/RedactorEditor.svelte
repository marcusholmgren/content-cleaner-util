<script lang="ts">
	import { RedactorState } from './redactor.svelte';
	import type { ScanResultPayload } from './types';

	let state = new RedactorState();

	let textarea: HTMLTextAreaElement;

	function handleInput(event: Event) {
		const target = event.target as HTMLTextAreaElement;
		state.handleInput(target.value);
	}

	function handleScroll() {
		if (textarea) {
			const highlightDiv = textarea.previousElementSibling as HTMLDivElement;
			if (highlightDiv) {
				highlightDiv.scrollTop = textarea.scrollTop;
				highlightDiv.scrollLeft = textarea.scrollLeft;
			}
		}
	}

	async function copyRedacted() {
		await navigator.clipboard.writeText(state.sanitizedText);
		alert('Copied redacted text to clipboard!');
	}

	function getHighlightedText(text: string, entities: ScanResultPayload['entities']) {
		if (!entities.length) return text;

		let result = '';
		let lastIndex = 0;

		for (const entity of entities) {
			if (entity.start < lastIndex) continue;

			result += text.slice(lastIndex, entity.start);
			result += `<span class="bg-yellow-200 text-transparent">${text.slice(entity.start, entity.end)}</span>`;
			lastIndex = entity.end;
		}
		result += text.slice(lastIndex);

		return result;
	}
</script>

<div class="mx-auto flex max-w-3xl flex-col gap-4 p-4">
	<div class="flex items-center justify-between">
		<h2 class="text-xl font-bold">PII Redactor</h2>
		<div class="flex items-center gap-4">
			<span class="text-sm text-gray-500">
				{#if state.isProcessing}
					Processing...
				{:else}
					Idle
				{/if}
			</span>
			<button
				class="rounded bg-blue-500 px-4 py-2 text-white hover:bg-blue-600 disabled:opacity-50"
				onclick={copyRedacted}
				disabled={state.rawText.length === 0}
			>
				Copy Redacted
			</button>
		</div>
	</div>

	<div class="relative h-64 w-full overflow-hidden rounded border bg-white">
		<!-- Highlight Layer -->
		<div
			class="pointer-events-none absolute inset-0 overflow-auto p-3 font-mono text-sm leading-normal break-words whitespace-pre-wrap text-transparent"
			aria-hidden="true"
		>
			<!-- eslint-disable-next-line svelte/no-at-html-tags -->
			{@html getHighlightedText(state.rawText, state.entities)}
		</div>

		<!-- Input Layer -->
		<textarea
			bind:this={textarea}
			class="absolute inset-0 h-full w-full resize-none bg-transparent p-3 font-mono text-sm leading-normal text-black caret-black focus:ring-2 focus:ring-blue-500 focus:outline-none"
			value={state.rawText}
			oninput={handleInput}
			onscroll={handleScroll}
			placeholder="Paste your text here..."></textarea>
	</div>

	{#if state.entities.length > 0}
		<div class="mt-4">
			<h3 class="mb-2 font-semibold">Detected Entities:</h3>
			<div class="flex flex-wrap gap-2">
				{#each state.entities as entity, i (i)}
					<span class="rounded bg-gray-100 px-2 py-1 font-mono text-xs">
						{entity.type} ({entity.confidence.toFixed(2)})
					</span>
				{/each}
			</div>
		</div>
	{/if}
</div>
