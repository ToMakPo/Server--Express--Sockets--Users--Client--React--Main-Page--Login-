/** Add a message to the input group.
 * 
 * @param {HTMLElement} inputGroup - The input group element.
 * @param {boolean} passed - If true, the message is a success message, otherwise it is an error message.
 * @param {string} message - The message to display.
 * @param {boolean} [clear=true] - If true, clears the message box before adding the new message.
 * @param {boolean} [updateIcon=true] - If true, updates the icon to indicate success or error.
 */
export const addMsg = (inputGroup, passed, message, clear=true, updateIcon=true) => {
	const iconEl = inputGroup.querySelector('.icon')
	const dialogEl = inputGroup.querySelector('dialog')

	if (clear) {
		dialogEl.innerHTML = ''
		iconEl.innerHTML = ''
	}

	if (passed) {
		if (updateIcon) {
			iconEl.innerHTML = 'check_circle'
			iconEl.style.color = 'forestgreen'
		}
		if (!message) return

		const messageEl = document.createElement('p')
		dialogEl.appendChild(messageEl)
		messageEl.style.color = 'forestgreen'

		const msgIconEl = document.createElement('span')
		messageEl.appendChild(msgIconEl)
		msgIconEl.innerHTML = 'done'
		msgIconEl.classList.add('icon')

		messageEl.appendChild(document.createTextNode(message))
	} else {
		if (updateIcon) {
			iconEl.innerHTML = 'dangerous'
			iconEl.style.color = 'firebrick'
		}
		if (!message) return
		
		const messageEl = document.createElement('p')
		dialogEl.appendChild(messageEl)
		messageEl.style.color = 'firebrick'

		const msgIconEl = document.createElement('span')
		messageEl.appendChild(msgIconEl)
		msgIconEl.innerHTML = 'clear'
		msgIconEl.classList.add('icon')

		messageEl.appendChild(document.createTextNode(message))
	}
}