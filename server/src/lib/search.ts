/**
 * This will take a search string and return a regular expression object.
 *
 * There are several options for the search string:
 * Provide an empty string to return an empty regular expression object.
 *
 * By default, the search is case sensitive. Add a ``~`` at the beginning of the search
 * string to make it case insensitive.
 *
 * You can use wildcards in the search string:\
 *  ``*`` - matches zero or more characters (e.g. ``c*t`` would match "cat", "cot",
 * 		"coast", etc.)\
 *  ``?`` - matches exactly one character (e.g. ``?at`` would match "cat", "bat", "rat",
 * 		etc.)\
 *  ``#`` - matches exactly one digit (e.g. ``Lot number 25#`` would match "Lot number
 * 		251", "Lot number 255", etc.)\
 *  ``^`` - matches zero or more digits (e.g. ``Lot number 25^`` would match "Lot number
 * 		25", "Lot number 251", "Lot number 2595", etc.)
 *
 * You can have multiple wildcards in the search string. (e.g. ``Lot number 25#^``
 * would not match "Lot number 25" since it requires at least one digit after the 25,
 * but it would match "Lot number 251", "Lot number 2595", etc.)
 *
 * You can use ``!`` to escape the special wildcard characters. For example, to search
 * for a string that contains an asterisk, you would use ```!*``` in the search string.
 * (e.g. ``Home world !*25`` would match "Home world *25")
 *
 * Use ```!!``` to escape the exclamation mark if it comes before a wildcard character.
 * (e.g. ```Welcome home!!*``` Welcome home!!* would match "Welcome home! I missed you!")
 *
 * Alternatively, you can use regular expressions by enclosing the search string
 * in forward slashes ``/``. You can even add flags after the closing slash. (e.g.
 * ``/^Hello .+? Smith$/i`` would match "Hello John Smith", "Hello Jane Smith",
 * "Hello Mr. Smith", etc.)
 *
 * @param searchString The search string
 *
 * @returns {RegExp} A regular expression object
 */
export const buildRegex = (searchString: string, addFlag?: string) => {
	if (searchString === '') return new RegExp('^')

	if (new RegExp(/^\/.*\/[dgimsuvy]*$/).test(searchString)) {
		const rxString = searchString.replace(/^\/(.*)\/[dgimsuvy]*$/, '$1')
		const flags = searchString.replace(/^\/.*\/([dgimsuvy]*)$/, '$1')
		return new RegExp(rxString, flags)
	}

	const escapedExclamationMark = 'xxxESCAPED_EXCLAMATION_MARKxxx'
	const escapedAsterisk = 'xxxESCAPED_ASTERISKxxx'
	const escapedQuestionMark = 'xxxESCAPED_QUESTION_MARKxxx'
	const escapedHashMark = 'xxxESCAPED_HASH_MARKxxx'
	const escapedCaret = 'xxxESCAPED_CARETxxx'
	const escapedTilde = 'xxxESCAPED_TILDExxx'
	const tempSingleChar = 'xxxTEMP_SINGLE_CHARxxx'
	const tempMultiChar = 'xxxTEMP_MULTI_CHARxxx'
	const tempSingleDigit = 'xxxTEMP_SINGLE_DIGITxxx'
	const tempMultiDigit = 'xxxTEMP_MULTI_DIGITxxx'

	const rxString = searchString
		.replace(/!!/g, escapedExclamationMark)
		.replace(/!\*/g, escapedAsterisk)
		.replace(/!\?/g, escapedQuestionMark)
		.replace(/!#/g, escapedHashMark)
		.replace(/!\^/g, escapedCaret)
		.replace(/^!~/g, escapedTilde)
		.replace(/\*/g, tempMultiChar)
		.replace(/\?/g, tempSingleChar)
		.replace(/#/g, tempSingleDigit)
		.replace(/\^/g, tempMultiDigit)
		.replace(/^~/, '')
		.replace(/([^a-zA-Z0-9\s\-_])/g, '\\$1')
		.replace(/\s/g, '\\s')
		.replace(new RegExp(escapedExclamationMark, 'g'), '\\!')
		.replace(new RegExp(escapedAsterisk, 'g'), '\\*')
		.replace(new RegExp(escapedQuestionMark, 'g'), '\\?')
		.replace(new RegExp(escapedHashMark, 'g'), '\\#')
		.replace(new RegExp(escapedCaret, 'g'), '\\^')
		.replace(new RegExp(escapedTilde, 'g'), '\\~')
		.replace(new RegExp(tempSingleChar, 'g'), '.')
		.replace(new RegExp(tempMultiChar, 'g'), '.*?')
		.replace(new RegExp(tempSingleDigit, 'g'), '\\d')
		.replace(new RegExp(tempMultiDigit, 'g'), '\\d*?')
	let flags = searchString.startsWith('~') ? 'i' : ''

	// if addFlag is not undefined, split it up and if the flag is not already in the flags string, add it
	if (addFlag !== undefined) {
		const flagsArray = flags.split('')
		const addFlags = addFlag.split('')
		for (const flag of addFlags) {
			if (!flagsArray.includes(flag)) flags += flag
		}
	}

	return new RegExp('^' + rxString + '$', flags)
}

/**
 * This will take a search string and a target string and return a boolean value
 * indicating whether the target string matches the search string.
 *
 * There are several options for the search string:
 * Provide an empty string to return false.
 *
 * By default, the search is case sensitive. Add a ``~`` at the beginning of the search
 * string to make it case insensitive.
 *
 * You can use wildcards in the search string:\
 *  ``*`` - matches zero or more characters (e.g. ``c*t`` would match "cat", "cot",
 * 		"coast", etc.)\
 *  ``?`` - matches exactly one character (e.g. ``?at`` would match "cat", "bat", "rat",
 * 		etc.)\
 *  ``#`` - matches exactly one digit (e.g. ``Lot number 25#`` would match "Lot number
 * 		251", "Lot number 255", etc.)\
 *  ``^`` - matches zero or more digits (e.g. ``Lot number 25^`` would match "Lot number
 * 		25", "Lot number 251", "Lot number 2595", etc.)
 *
 * You can have multiple wildcards in the search string. (e.g. ``Lot number 25#^``
 * would not match "Lot number 25" since it requires at least one digit after the 25,
 * but it would match "Lot number 251", "Lot number 2595", etc.)
 *
 * You can use ``!`` to escape the special wildcard characters. For example, to search
 * for a string that contains an asterisk, you would use ```!*``` in the search string.
 * (e.g. ``Home world !*25`` would match "Home world *25")
 *
 * Use ```!!``` to escape the exclamation mark if it comes before a wildcard character.
 * (e.g. ```Welcome home!!*``` Welcome home!!* would match "Welcome home! I missed you!")
 *
 * Alternatively, you can use regular expressions by enclosing the search string
 * in forward slashes ``/``. You can even add flags after the closing slash. (e.g.
 * ``/^Hello .+? Smith$/i`` would match "Hello John Smith", "Hello Jane Smith",
 * "Hello Mr. Smith", etc.)
 *
 * @param searchString The search string
 * @param target The target string
 *
 * @returns {boolean} A boolean value indicating whether the target string matches the search string
 */
export const fuzzySearch = (searchString: string, target: string): boolean => {
	return buildRegex(searchString).test(target)
}

/**
 * This will take a search string and a list of target strings and return a list of
 * strings that match the search string.
 *
 * There are several options for the search string:
 * Provide an empty string to return the entire list.
 *
 * By default, the search is case sensitive. Add a ``~`` at the beginning of the search
 * string to make it case insensitive.
 *
 * You can use wildcards in the search string:\
 *  ``*`` - matches zero or more characters (e.g. ``c*t`` would match "cat", "cot",
 * 		"coast", etc.)\
 *  ``?`` - matches exactly one character (e.g. ``?at`` would match "cat", "bat", "rat",
 * 		etc.)\
 *  ``#`` - matches exactly one digit (e.g. ``Lot number 25#`` would match "Lot number
 * 		251", "Lot number 255", etc.)\
 *  ``^`` - matches zero or more digits (e.g. ``Lot number 25^`` would match "Lot number
 * 		25", "Lot number 251", "Lot number 2595", etc.)
 *
 * You can have multiple wildcards in the search string. (e.g. ``Lot number 25#^``
 * would not match "Lot number 25" since it requires at least one digit after the 25,
 * but it would match "Lot number 251", "Lot number 2595", etc.)
 *
 * You can use ``!`` to escape the special wildcard characters. For example, to search
 * for a string that contains an asterisk, you would use ```!*``` in the search string.
 * (e.g. ``Home world !*25`` would match "Home world *25")
 *
 * Use ```!!``` to escape the exclamation mark if it comes before a wildcard character.
 * (e.g. ```Welcome home!!*``` Welcome home!!* would match "Welcome home! I missed you!")
 *
 * Alternatively, you can use regular expressions by enclosing the search string
 * in forward slashes ``/``. You can even add flags after the closing slash. (e.g.
 * ``/^Hello .+? Smith$/i`` would match "Hello John Smith", "Hello Jane Smith",
 * "Hello Mr. Smith", etc.)
 *
 * @param {string} searchString The search string
 * @param {string[]} targetList The list of target strings
 *
 * @returns {string[]} A list of strings that match the search string
 */
export const multiSearch = (searchString: string, targetList: string[]): string[] => {
	if (searchString === '') return targetList

	const regex = buildRegex(searchString)
	return targetList.filter(target => regex.test(target))
}
