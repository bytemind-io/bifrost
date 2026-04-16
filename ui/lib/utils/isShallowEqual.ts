export function isShallowEqual(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
	const aKeys = Object.keys(a);
	const bKeys = Object.keys(b);

	if (aKeys.length !== bKeys.length) {
		return false;
	}

	for (const key of aKeys) {
		if (!Object.prototype.hasOwnProperty.call(b, key) || !Object.is(a[key], b[key])) {
			return false;
		}
	}

	return true;
}
