<script lang="ts">
	import { onDestroy } from 'svelte';
	import { buildHighlightSegments, getViewportCharRange } from './Engine';
	import { RedactorState } from './redactor.svelte';
	import type { EntityType, RedactionEntity } from './types';

	const redactorState = new RedactorState();

	let textarea: HTMLTextAreaElement | undefined = $state();
	let highlightDiv: HTMLDivElement | undefined = $state();
	let scrollTop = $state(0);
	let viewportHeight = $state(256);
	let copied = $state(false);
	let copyTimeout: ReturnType<typeof setTimeout> | null = null;

	const FILTERABLE_TYPES: Array<{ type: EntityType; label: string }> = [
		{ type: 'PER', label: 'Names (PER)' },
		{ type: 'ORG', label: 'Organizations (ORG)' },
		{ type: 'LOC', label: 'Locations (LOC)' },
		{ type: 'EMAIL', label: 'Emails' },
		{ type: 'IP', label: 'IP Addresses' },
		{ type: 'TOKEN', label: 'Tokens & Secrets' },
		{ type: 'CREDIT_CARD', label: 'Credit Cards' }
	];

	const viewportRange = $derived(
		getViewportCharRange(redactorState.rawText, scrollTop, viewportHeight, 21, 200)
	);

	const highlightSegments = $derived(
		buildHighlightSegments(redactorState.rawText, redactorState.entities, viewportRange)
	);

	function handleInput(event: Event) {
		const target = event.target as HTMLTextAreaElement;
		redactorState.handleInput(target.value);
		syncScroll();
	}

	function syncScroll() {
		if (textarea) {
			scrollTop = textarea.scrollTop;
			viewportHeight = textarea.clientHeight || 256;
			if (highlightDiv) {
				highlightDiv.scrollTop = textarea.scrollTop;
				highlightDiv.scrollLeft = textarea.scrollLeft;
			}
		}
	}

	function handleTextareaClick() {
		if (!textarea) return;
		if (textarea.selectionStart !== textarea.selectionEnd) return;
		const pos = textarea.selectionStart;

		// If the user clicks directly on an ambiguous entity inside the editor, toggle its redaction state
		const idx = redactorState.entities.findIndex(
			(e) =>
				(e.ambiguous || e.type === 'AMBIGUOUS_PER' || e.type === 'AMBIGUOUS_ORG') &&
				pos >= e.start &&
				pos <= e.end
		);
		if (idx !== -1) {
			redactorState.toggleEntityRedaction(idx);
		}
	}

	async function copyRedacted() {
		const verification = redactorState.verifyBeforeCopy();
		if (typeof navigator !== 'undefined' && navigator.clipboard) {
			await navigator.clipboard.writeText(redactorState.sanitizedText);
		}
		if (verification.valid) {
			copied = true;
			if (copyTimeout) clearTimeout(copyTimeout);
			copyTimeout = setTimeout(() => {
				copied = false;
			}, 2000);
		}
	}

	function getHighlightClass(entity: RedactionEntity): string {
		const isAmbiguous =
			entity.ambiguous || entity.type === 'AMBIGUOUS_PER' || entity.type === 'AMBIGUOUS_ORG';

		if (isAmbiguous) {
			if (entity.redacted) {
				return 'bg-yellow-200/80 underline decoration-yellow-500 decoration-dotted decoration-2 rounded-xs';
			}
			return 'underline decoration-yellow-500 decoration-dotted decoration-2 rounded-xs';
		}

		if (entity.redacted === false) {
			return 'underline decoration-gray-400 decoration-dotted rounded-xs';
		}

		if (entity.source === 'REGEX') {
			return 'bg-red-200/75 rounded-xs';
		}

		return 'bg-yellow-200/80 rounded-xs';
	}

	onDestroy(() => {
		if (copyTimeout) clearTimeout(copyTimeout);
		redactorState.destroy();
	});
</script>

<div class="mx-auto flex max-w-3xl flex-col gap-4 p-4">
	<div class="flex flex-wrap items-center justify-between gap-2">
		<h2 class="text-xl font-bold text-gray-900">PII Redactor</h2>
		<div class="flex items-center gap-4">
			<span
				class="rounded-full bg-gray-100 px-3 py-1 text-xs font-medium text-gray-700"
				data-testid="status-indicator"
			>
				{redactorState.statusText}
			</span>
			<button
				type="button"
				class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700 disabled:opacity-50"
				onclick={copyRedacted}
				disabled={redactorState.rawText.length === 0}
			>
				{copied ? 'Copied!' : 'Copy Redacted'}
			</button>
		</div>
	</div>

	<!-- Configuration Bar -->
	<div
		class="flex flex-wrap items-center justify-between gap-3 rounded border border-gray-200 bg-white p-3 text-xs"
	>
		<div class="flex flex-wrap items-center gap-2">
			<span class="font-semibold text-gray-700">Detect:</span>
			{#each FILTERABLE_TYPES as item (item.type)}
				<button
					type="button"
					class="rounded border px-2 py-1 transition {redactorState.enabledTypes.includes(item.type)
						? 'border-blue-500 bg-blue-50 text-blue-700'
						: 'border-gray-200 bg-gray-50 text-gray-500'}"
					onclick={() => redactorState.toggleEntityType(item.type)}
				>
					{item.label}
				</button>
			{/each}
		</div>

		<label class="flex cursor-pointer items-center gap-1.5 font-medium text-gray-700">
			<input
				type="checkbox"
				class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
				checked={redactorState.aggressiveMode}
				onchange={(e) => redactorState.setAggressiveMode((e.target as HTMLInputElement).checked)}
			/>
			Aggressive Mode
		</label>
	</div>

	{#if redactorState.verificationWarnings.length > 0}
		<div
			class="rounded border border-amber-400 bg-amber-50 p-3 text-sm text-amber-900"
			role="alert"
			data-testid="verification-warning"
		>
			{#each redactorState.verificationWarnings as warning, i (i)}
				<p class="font-medium">{warning}</p>
			{/each}
		</div>
	{/if}

	{#if redactorState.errorMessage}
		<div class="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800" role="alert">
			{redactorState.errorMessage}
		</div>
	{/if}

	<!-- Twin-Layer Synchronized Editor -->
	<div class="relative h-64 w-full overflow-hidden rounded border border-gray-300 bg-white">
		<!-- Highlight Layer -->
		<div
			bind:this={highlightDiv}
			class="pointer-events-none absolute inset-0 overflow-auto p-3 font-mono text-sm leading-normal break-words whitespace-pre-wrap text-transparent"
			aria-hidden="true"
			data-testid="highlight-layer"
		>
			{#each highlightSegments as segment, i (i)}{#if segment.entity}<span
						class="{getHighlightClass(segment.entity)} text-transparent"
						data-entity-type={segment.entity.type}
						data-ambiguous={segment.entity.ambiguous ? 'true' : undefined}
						data-redacted={segment.entity.redacted !== false ? 'true' : 'false'}
						>{segment.text}</span
					>{:else}{segment.text}{/if}{/each}{#if redactorState.rawText.endsWith('\n')}<br />{/if}
		</div>

		<!-- Input Layer -->
		<textarea
			bind:this={textarea}
			class="absolute inset-0 h-full w-full resize-none overflow-auto bg-transparent p-3 font-mono text-sm leading-normal break-words whitespace-pre-wrap text-gray-900 caret-black focus:ring-2 focus:ring-blue-500 focus:outline-none"
			value={redactorState.rawText}
			oninput={handleInput}
			onscroll={syncScroll}
			onclick={handleTextareaClick}
			placeholder="Paste your text here..."></textarea>
	</div>

	{#if redactorState.entities.length > 0}
		<div class="mt-2 flex flex-col gap-3">
			<div>
				<h3 class="mb-2 text-sm font-semibold text-gray-800">
					Detected Entities (click to toggle redaction):
				</h3>
				<div class="flex flex-wrap gap-2">
					{#each redactorState.entities as entity, i (`${entity.start}-${entity.end}-${entity.type}-${i}`)}
						<button
							type="button"
							onclick={() => redactorState.toggleEntityRedaction(i)}
							class="cursor-pointer rounded border px-2 py-1 font-mono text-xs transition {entity.ambiguous ||
							entity.type === 'AMBIGUOUS_PER' ||
							entity.type === 'AMBIGUOUS_ORG'
								? 'border-yellow-400 bg-yellow-50 text-yellow-900 underline decoration-yellow-500 decoration-dotted'
								: entity.redacted === false
									? 'border-gray-200 bg-gray-50 text-gray-400 line-through'
									: 'border-gray-300 bg-gray-100 text-gray-800'}"
							title="Click to toggle between redacted and preserved state"
						>
							{entity.type} ({entity.confidence.toFixed(2)})
							{entity.redacted === false ? '[Preserved]' : '[Redacted]'}
						</button>
					{/each}
				</div>
			</div>

			<div class="rounded border border-gray-200 bg-gray-50 p-3">
				<h3 class="mb-1 text-xs font-semibold tracking-wide text-gray-500 uppercase">
					Sanitized Output Preview
				</h3>
				<pre
					class="max-h-40 overflow-auto font-mono text-xs leading-relaxed break-words whitespace-pre-wrap text-gray-800"
					data-testid="sanitized-preview">{redactorState.sanitizedText}</pre>
			</div>
		</div>
	{/if}
</div>
