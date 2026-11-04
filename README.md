# Content Cleaner Util (PII Redactor)

A client-side Svelte 5 application that detects and redacts Personally Identifiable Information (PII) using a hybrid Regex and Web Worker-based NER (Named Entity Recognition) pipeline.

## Features

- **Hybrid Detection Engine**:
  - **Deterministic Regex & Heuristics**: Detects emails, IPv4/IPv6 addresses, API keys / secrets (GitHub, AWS, Stripe, Slack, JWT, UUID), credit card numbers (with Luhn validation), and high-entropy secret tokens.
  - **Machine Learning NER**: In-browser Named Entity Recognition via `@huggingface/transformers` running in a dedicated Web Worker sandbox (WebGPU with WASM fallback).
- **Two-Layer Synchronized Editor**: Syntax-highlighted overlay decoupled from the transparent input textarea.
- **Ambiguous Entity Support**: Interactive click-to-toggle redaction for ambiguous proper nouns and medium-confidence detections.
- **Verification on Copy**: Pre-copy sanity checks for residual unmasked sensitive data (such as SSNs).

## Development

```sh
npm install
npm run dev
```

## Testing & Quality Checks

```sh
npm run check      # Svelte TypeScript check
npm run lint       # ESLint & Prettier
npm test           # Vitest unit and browser component tests
```

## Building for Production

```sh
npm run build
npm run preview
```

## Deployment

The app is built as a static site using `@sveltejs/adapter-static` and automatically deployed to GitHub Pages via GitHub Actions upon pushes to `main`.
