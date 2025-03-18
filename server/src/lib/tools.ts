/**
 * Parse a string to a boolean.
 *
 * The following values are considered true: true, 1, yes, y, on /
 * The following values are considered false: false, 0, no, n, off
 *
 * If the value is not recognized, undefined is returned.
 * The comparison is case-insensitive.
 *
 * @param value The value to parse
 *
 * @returns The parsed boolean value
 */
export const evaluateTruthiness = (value: string): boolean | null | undefined =>
	/^(true|1|yes|y|on|correct|right|ok|okay|o)$/i.test(value)
		? true
		: /^(false|0|no|n|off|incorrect|wrong|not|x)$/i.test(value)
			? false
			: /^(null|void|none|empty|blank|nothing|\?)$/i.test(value)
				? null
				: undefined
