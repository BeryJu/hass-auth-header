(() => {
	// Replace the frontend's _handleLogout() handler to redirect to the IdP single‑logout URL if configured.
	const SLO_ENDPOINT = "/api/auth_header/slo_url";
	const fetchSlo = async () => {
		try {
			const resp = await fetch(SLO_ENDPOINT, { cache: "no-cache" });
			return resp.ok ? resp.text() : "";
		} catch {
			return "";
		}
	};
	const patchLogout = async () => {
		const sloUrl = await fetchSlo();
		if (!sloUrl) return; // nothing to do
		await customElements.whenDefined("home-assistant");
		const proto = customElements.get("home-assistant").prototype;
		if (!proto._handleLogout) return;
		const orig = proto._handleLogout;
		proto._handleLogout = async function () {
			await orig.call(this);
			window.location.href = sloUrl;
		};
	};
	patchLogout();
})();
