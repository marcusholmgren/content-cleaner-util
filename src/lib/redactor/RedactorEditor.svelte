<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { buildHighlightSegments, getViewportCharRange, validateCustomRule } from './Engine';
	import { RedactorState } from './redactor.svelte';
	import type { CustomRule, CustomRuleType, EntityType, RedactionEntity } from './types';

	const redactorState = new RedactorState();

	let textarea: HTMLTextAreaElement | undefined = $state();
	let highlightDiv: HTMLDivElement | undefined = $state();
	let scrollTop = $state(0);
	let viewportHeight = $state(256);
	let copied = $state(false);
	let copyTimeout: ReturnType<typeof setTimeout> | null = null;

	// Custom Rule Builder form state
	let newRuleType: CustomRuleType = $state('PHRASE');
	let newRuleValue = $state('');
	let newRuleCaseSensitive = $state(false);
	let ruleFormError: string | null = $state(null);

	// Inline editing state for existing custom rules
	let editingRuleId: string | null = $state(null);
	let editRuleType: CustomRuleType = $state('PHRASE');
	let editRuleValue = $state('');
	let editRuleError: string | null = $state(null);

	// Tooltip inspector state
	let inspectedEntityIndex: number | null = $state(null);

	const FILTERABLE_TYPES: Array<{ type: EntityType; label: string }> = [
		{ type: 'PER', label: 'Names (PER)' },
		{ type: 'ORG', label: 'Organizations (ORG)' },
		{ type: 'LOC', label: 'Locations (LOC)' },
		{ type: 'EMAIL', label: 'Emails' },
		{ type: 'IP', label: 'IP Addresses' },
		{ type: 'TOKEN', label: 'Tokens & Secrets' },
		{ type: 'CREDIT_CARD', label: 'Credit Cards' },
		{ type: 'CUSTOM_RULE', label: 'Custom Dictionary' }
	];

	const viewportRange = $derived(
		getViewportCharRange(redactorState.rawText, scrollTop, viewportHeight, 21, 200)
	);

	const highlightSegments = $derived(
		buildHighlightSegments(redactorState.rawText, redactorState.entities, viewportRange)
	);

	const inspectedEntity = $derived(
		inspectedEntityIndex !== null ? (redactorState.entities[inspectedEntityIndex] ?? null) : null
	);

	onMount(() => {
		void redactorState.init();
	});

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

		const clickedIdx = redactorState.entities.findIndex((e) => pos >= e.start && pos <= e.end);

		if (clickedIdx !== -1) {
			inspectedEntityIndex = clickedIdx;
			const entity = redactorState.entities[clickedIdx];
			if (entity.ambiguous || entity.type === 'AMBIGUOUS_PER' || entity.type === 'AMBIGUOUS_ORG') {
				redactorState.toggleEntityRedaction(clickedIdx);
			}
		} else {
			inspectedEntityIndex = null;
		}
	}

	async function handleAddRuleSubmit(event: SubmitEvent) {
		event.preventDefault();
		ruleFormError = null;

		const validation = validateCustomRule(newRuleType, newRuleValue);
		if (!validation.valid) {
			ruleFormError = validation.error ?? 'Invalid custom rule.';
			return;
		}

		const result = await redactorState.addCustomRule({
			type: newRuleType,
			value: newRuleValue,
			caseSensitive: newRuleCaseSensitive,
			enabled: true
		});

		if (!result.ok) {
			ruleFormError = result.error ?? 'Could not add custom rule.';
			return;
		}

		newRuleValue = '';
	}

	function startEditingRule(rule: CustomRule) {
		editingRuleId = rule.id;
		editRuleType = rule.type;
		editRuleValue = rule.value;
		editRuleError = null;
	}

	function cancelEditingRule() {
		editingRuleId = null;
		editRuleValue = '';
		editRuleError = null;
	}

	async function saveEditedRule(id: string) {
		editRuleError = null;
		const result = await redactorState.updateCustomRule(id, {
			type: editRuleType,
			value: editRuleValue
		});
		if (!result.ok) {
			editRuleError = result.error ?? 'Invalid rule update.';
			return;
		}
		editingRuleId = null;
		editRuleValue = '';
	}

	async function copyRedacted(forceOverride = false) {
		if (!redactorState.canCopy) return;

		const verification = redactorState.verifyBeforeCopy();
		if (!verification.valid && !forceOverride) {
			return;
		}

		if (typeof navigator !== 'undefined' && navigator.clipboard) {
			await navigator.clipboard.writeText(redactorState.sanitizedText);
		}

		copied = true;
		if (copyTimeout) clearTimeout(copyTimeout);
		copyTimeout = setTimeout(() => {
			copied = false;
		}, 2000);
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

		if (entity.source === 'CUSTOM' || entity.type === 'CUSTOM_RULE') {
			return 'bg-purple-200/75 underline decoration-purple-600 decoration-dashed decoration-2 rounded-xs';
		}

		if (entity.source === 'REGEX') {
			return 'bg-red-200/75 rounded-xs';
		}

		return 'bg-yellow-200/80 rounded-xs';
	}

	function getEntityInspectorLabel(entity: RedactionEntity): string {
		const matchedText = redactorState.rawText.slice(entity.start, entity.end);
		if (entity.source === 'CUSTOM' || entity.type === 'CUSTOM_RULE') {
			return `Custom Rule Matched: "${entity.ruleValue ?? matchedText}"`;
		}
		if (entity.source === 'REGEX') {
			return `Built-in Regex Matched (${entity.type}): "${matchedText}"`;
		}
		return `NER Model Matched (${entity.type}, ${(entity.confidence * 100).toFixed(0)}%): "${matchedText}"`;
	}

	onDestroy(() => {
		if (copyTimeout) clearTimeout(copyTimeout);
		redactorState.destroy();
	});
</script>

<div class="mx-auto flex max-w-4xl flex-col gap-4 p-4">
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
				onclick={() => copyRedacted(false)}
				disabled={!redactorState.canCopy}
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
			class="flex flex-wrap items-center justify-between gap-3 rounded border border-amber-400 bg-amber-50 p-3 text-sm text-amber-900"
			role="alert"
			data-testid="verification-warning"
		>
			<div class="flex flex-col gap-1">
				{#each redactorState.verificationWarnings as warning, i (i)}
					<p class="font-medium">{warning}</p>
				{/each}
			</div>
			{#if redactorState.canCopy}
				<button
					type="button"
					class="rounded bg-amber-700 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-amber-800"
					data-testid="copy-override-btn"
					onclick={() => copyRedacted(true)}
				>
					Copy Anyway
				</button>
			{/if}
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
						data-entity-source={segment.entity.source}
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

	{#if redactorState.verificationReports.length > 0}
		<div class="mt-3 flex flex-wrap gap-2" data-testid="verification-status-panel">
			{#each redactorState.verificationReports as report (report.ruleId)}
				<span
					class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium"
					class:bg-green-50={report.status === 'NOT_DETECTED'}
					class:text-green-700={report.status === 'NOT_DETECTED'}
					class:border-green-200={report.status === 'NOT_DETECTED'}
					class:bg-red-50={report.status === 'DETECTED'}
					class:text-red-700={report.status === 'DETECTED'}
					class:border-red-200={report.status === 'DETECTED'}
					class:bg-yellow-50={report.status === 'INVALID_FORMAT'}
					class:text-yellow-700={report.status === 'INVALID_FORMAT'}
					class:border-yellow-200={report.status === 'INVALID_FORMAT'}
				>
					{#if report.status === 'NOT_DETECTED'}
						✅
					{:else}
						❌
					{/if}
					&nbsp;{report.message}
				</span>
			{/each}
		</div>
	{/if}

	{#if redactorState.entities.length > 0}
		<div class="mt-1 flex flex-col gap-3">
			<div>
				<h3 class="mb-2 text-sm font-semibold text-gray-800">
					Detected Entities (hover to inspect, click to toggle redaction):
				</h3>
				<div class="flex flex-wrap gap-2">
					{#each redactorState.entities as entity, i (`${entity.start}-${entity.end}-${entity.type}-${i}`)}
						<button
							type="button"
							onclick={() => {
								inspectedEntityIndex = i;
								redactorState.toggleEntityRedaction(i);
							}}
							onmouseenter={() => {
								inspectedEntityIndex = i;
							}}
							onfocus={() => {
								inspectedEntityIndex = i;
							}}
							class="cursor-pointer rounded border px-2 py-1 font-mono text-xs transition {entity.ambiguous ||
							entity.type === 'AMBIGUOUS_PER' ||
							entity.type === 'AMBIGUOUS_ORG'
								? 'border-yellow-400 bg-yellow-50 text-yellow-900 underline decoration-yellow-500 decoration-dotted'
								: entity.redacted === false
									? 'border-gray-200 bg-gray-50 text-gray-400 line-through'
									: entity.source === 'CUSTOM' || entity.type === 'CUSTOM_RULE'
										? 'border-purple-400 bg-purple-50 text-purple-900 underline decoration-purple-600 decoration-dashed'
										: 'border-gray-300 bg-gray-100 text-gray-800'}"
							title={getEntityInspectorLabel(entity)}
						>
							{entity.type} ({entity.confidence.toFixed(2)})
							{entity.redacted === false ? '[Preserved]' : '[Redacted]'}
						</button>
					{/each}
				</div>

				{#if inspectedEntity}
					<div
						class="mt-2 flex items-center justify-between rounded border border-purple-200 bg-purple-50/70 px-3 py-1.5 font-mono text-xs text-purple-950"
						data-testid="entity-inspector-tooltip"
					>
						<span>{getEntityInspectorLabel(inspectedEntity)}</span>
						<button
							type="button"
							class="ml-3 text-xs text-gray-500 hover:text-gray-800"
							onclick={() => {
								inspectedEntityIndex = null;
							}}
						>
							Dismiss
						</button>
					</div>
				{/if}
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

	<!-- Custom Redaction Dictionary & Rule Manager -->
	<section
		class="mt-2 rounded border border-gray-200 bg-white p-4 shadow-2xs"
		aria-labelledby="custom-dictionary-heading"
		data-testid="custom-dictionary-section"
	>
		<div class="mb-3 flex items-center justify-between">
			<div>
				<h3 id="custom-dictionary-heading" class="text-base font-semibold text-gray-900">
					Custom Redaction Dictionary
				</h3>
				<p class="text-xs text-gray-500">
					Add custom phrases, exact words, or regular expressions to always redact (takes priority
					over NER).
				</p>
			</div>
			<span class="rounded-full bg-purple-100 px-2.5 py-0.5 text-xs font-medium text-purple-800">
				{redactorState.customRuleStore.rules.length}
				{redactorState.customRuleStore.rules.length === 1 ? 'rule' : 'rules'}
			</span>
		</div>

		<!-- Add Custom Phrase / Rule Form -->
		<form onsubmit={handleAddRuleSubmit} class="mb-4">
			<fieldset class="flex flex-col gap-3">
				<legend class="sr-only">Add a custom redaction phrase or pattern</legend>
				<div class="flex flex-wrap items-end gap-3">
					<div class="flex flex-col gap-1">
						<label for="custom-rule-type" class="text-xs font-medium text-gray-700">
							Rule Type
						</label>
						<select
							id="custom-rule-type"
							name="ruleType"
							bind:value={newRuleType}
							onchange={() => {
								ruleFormError = null;
							}}
							class="rounded border border-gray-300 bg-white px-2.5 py-1.5 text-xs text-gray-900 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
						>
							<option value="PHRASE">Phrase Match</option>
							<option value="EXACT">Exact Word</option>
							<option value="REGEX">Regular Expression</option>
						</select>
					</div>

					<div class="flex min-w-56 flex-1 flex-col gap-1">
						<label for="custom-rule-value" class="text-xs font-medium text-gray-700">
							Custom Phrase or Pattern
						</label>
						<input
							id="custom-rule-value"
							name="ruleValue"
							type="text"
							bind:value={newRuleValue}
							oninput={() => {
								if (ruleFormError) ruleFormError = null;
							}}
							aria-describedby={ruleFormError ? 'custom-rule-error' : undefined}
							placeholder={newRuleType === 'REGEX' ? 'e.g. PROJ-[0-9]{4}' : 'e.g. Project Titan'}
							class="w-full rounded border border-gray-300 px-3 py-1.5 font-mono text-xs text-gray-900 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
						/>
					</div>

					<label
						for="custom-rule-case"
						class="flex cursor-pointer items-center gap-1.5 pb-1.5 text-xs font-medium text-gray-700"
					>
						<input
							id="custom-rule-case"
							name="caseSensitive"
							type="checkbox"
							bind:checked={newRuleCaseSensitive}
							class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
						/>
						Match Case
					</label>

					<button
						type="submit"
						data-testid="add-custom-rule-btn"
						class="rounded bg-purple-600 px-3.5 py-1.5 text-xs font-medium text-white transition hover:bg-purple-700 disabled:opacity-50"
						disabled={!newRuleValue.trim()}
					>
						Add Phrase
					</button>
				</div>

				{#if ruleFormError}
					<p
						id="custom-rule-error"
						class="text-xs font-medium text-red-600"
						role="alert"
						aria-live="polite"
						data-testid="custom-rule-error"
					>
						{ruleFormError}
					</p>
				{/if}
			</fieldset>
		</form>

		<!-- Custom Rules List / Table -->
		{#if redactorState.customRuleStore.rules.length === 0}
			<p
				class="rounded border border-dashed border-gray-200 py-4 text-center text-xs text-gray-500"
				data-testid="empty-custom-rules"
			>
				No custom phrases added yet. Add a phrase, exact word, or regex above to redact it
				automatically.
			</p>
		{:else}
			<div class="overflow-x-auto rounded border border-gray-200">
				<table class="min-w-full divide-y divide-gray-200 text-left text-xs">
					<thead class="bg-gray-50 font-semibold text-gray-700">
						<tr>
							<th scope="col" class="px-3 py-2">Type</th>
							<th scope="col" class="px-3 py-2">Phrase / Pattern</th>
							<th scope="col" class="px-3 py-2">Match Case</th>
							<th scope="col" class="px-3 py-2">Enabled</th>
							<th scope="col" class="px-3 py-2 text-right">Actions</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-gray-200 bg-white">
						{#each redactorState.customRuleStore.rules as rule (rule.id)}
							<tr data-testid="custom-rule-row">
								<td class="px-3 py-2 whitespace-nowrap">
									{#if editingRuleId === rule.id}
										<select
											aria-label="Edit rule type"
											bind:value={editRuleType}
											class="rounded border border-gray-300 px-2 py-1 text-xs"
										>
											<option value="PHRASE">PHRASE</option>
											<option value="EXACT">EXACT</option>
											<option value="REGEX">REGEX</option>
										</select>
									{:else}
										<span
											class="inline-block rounded bg-purple-50 px-2 py-0.5 font-mono text-[11px] font-medium text-purple-800"
										>
											{rule.type}
										</span>
									{/if}
								</td>

								<td class="px-3 py-2 font-mono text-gray-900">
									{#if editingRuleId === rule.id}
										<div class="flex flex-col gap-1">
											<input
												type="text"
												aria-label="Edit rule value"
												bind:value={editRuleValue}
												class="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
											/>
											{#if editRuleError}
												<span class=" font-sans text-[11px] text-red-600">{editRuleError}</span>
											{/if}
										</div>
									{:else}
										<span class={!rule.enabled ? 'text-gray-400 line-through' : ''}>
											{rule.value}
										</span>
									{/if}
								</td>

								<td class="px-3 py-2 whitespace-nowrap">
									<input
										type="checkbox"
										aria-label="Match case for {rule.value}"
										checked={rule.caseSensitive}
										onchange={() => redactorState.toggleCustomRuleCaseSensitivity(rule.id)}
										class="rounded border-gray-300 text-purple-600 focus:ring-purple-500"
									/>
								</td>

								<td class="px-3 py-2 whitespace-nowrap">
									<input
										type="checkbox"
										aria-label="Enable rule {rule.value}"
										checked={rule.enabled}
										onchange={() => redactorState.toggleCustomRule(rule.id)}
										class="rounded border-gray-300 text-purple-600 focus:ring-purple-500"
									/>
								</td>

								<td class="px-3 py-2 text-right whitespace-nowrap">
									<div class="inline-flex items-center gap-2">
										{#if editingRuleId === rule.id}
											<button
												type="button"
												onclick={() => saveEditedRule(rule.id)}
												class="font-medium text-blue-600 hover:text-blue-800"
											>
												Save
											</button>
											<button
												type="button"
												onclick={cancelEditingRule}
												class="font-medium text-gray-500 hover:text-gray-700"
											>
												Cancel
											</button>
										{:else}
											<button
												type="button"
												onclick={() => startEditingRule(rule)}
												class="font-medium text-gray-600 hover:text-gray-900"
											>
												Edit
											</button>
											<button
												type="button"
												data-testid="remove-custom-rule-btn"
												onclick={() => redactorState.removeCustomRule(rule.id)}
												class="font-medium text-red-600 hover:text-red-800"
											>
												Remove
											</button>
										{/if}
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
</div>
