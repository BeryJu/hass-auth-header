(() => {
	// Store the login token in localStorage as soon as they are available. This is normally done (depending on whether the user enabled the "Keep me logged in" option) in https://github.com/home-assistant/frontend/blob/6653a8f63426755d6a58bce0ef3d55d83d8ec99c/src/common/auth/token_storage.ts
	let attemptsRemaining = 10;
	const interval = setInterval(() => {
		attemptsRemaining -= 1;
		if (window.__tokenCache.tokens) {
			localStorage.setItem("hassTokens", JSON.stringify(window.__tokenCache.tokens))
			window.__tokenCache.writeEnabled = true;
			attemptsRemaining = 0;
		}
		if (attemptsRemaining <= 0) {
			clearInterval(interval);
		}
	}, 1000);
})();
