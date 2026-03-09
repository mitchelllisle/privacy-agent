<div class="hero">
	<h1>Privacy Agent 🛡️</h1>
	<p>PII detection API with confidence scoring, field-path context, and clean deployment workflows.</p>
	<div class="hero-actions">
		<a class="cta-btn cta-btn-primary" href="./api/">Explore API Reference</a>
		<a class="cta-btn" href="https://github.com/mitchelllisle/privacy-agent">View on GitHub</a>
	</div>
</div>

<div class="quick-grid">
	<div class="quick-card">
		<strong>🔌 Endpoint</strong>
		<code>POST /run</code>
		<span>Main request surface for payload scanning.</span>
	</div>
	<div class="quick-card">
		<strong>🔎 Metrics</strong>
		<code>fields_scanned</code> and <code>fields_matched</code>
		<span>See what was processed and what was flagged.</span>
	</div>
	<div class="quick-card">
		<strong>📄 Docs source</strong>
		<span>Built from <code>README.md</code> and Python docstrings.</span>
	</div>
</div>

!!! tip "Quick start"
		Run <code>uv run privacy-agent</code> and open the API docs at <code>/docs</code>.

---

--8<-- "README.md"
