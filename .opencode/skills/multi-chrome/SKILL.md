---
name: multi-chrome
description: Orchestrates parallel multi-tab Chrome browser automation using Gemini Computer Use and Chrome DevTools MCP. Use for cross-tab scraping, side-by-side QA, and dashboard inspection.
---

# Multi-Agent Chrome Automation for Gemini

When triggered with `/multi-chrome <task>`:

## 1. Agent Roles
- **Coordinator (Gemini 2.5/3.5 Pro):** Deconstructs the prompt, allocates tasks to separate tab workers, and synthesizes results.
- **Scraper / Action Worker (Gemini Flash):** Navigates target URL, inspects DOM elements, inputs forms, and triggers downloads.
- **QA & Inspector Worker (Gemini Flash):** Watches network requests, captures console error logs, and runs UI assertions.

## 2. Multi-Tab Workflow
1. **Initialize Session:** Launch Playwright/Puppeteer with multi-tab context (`new_context()` -> `new_page()`).
2. **Execute Operations:**
   - Tab 1: Load main endpoint and carry out user actions.
   - Tab 2: Load reference site or comparator endpoint simultaneously.
3. **Capture Telemetry:** Record visual screenshots (`observe_screen`) and console messages.
4. **Synthesis:** Format extracted data and health status into the output template.

## 3. Output Format
- **Task Summary:** Target URLs and actions taken.
- **Cross-Tab Findings Table:** Compared attributes, values, or validation states.
- **Errors & Network Anomalies:** 4xx/5xx responses or console exceptions.
