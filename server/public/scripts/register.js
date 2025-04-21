import { addMsg } from './utils.js'
import { login } from './login.js'
function handleMsgIconClick() {	this.classList.toggle('show') }

//////////////////////
/// USERNAME INPUT ///
//////////////////////

/** Handles the username input field change event. **/
document.querySelector('#username-input')?.addEventListener('input', async function() {
	const inputGroup = document.querySelector('#username-group')
	const username = this.value.trim()
	await checkUsername(inputGroup, username, true)
})

/** Handles the username group icon click event. **/
document.querySelector('#username-group .msg-icon')?.addEventListener('click', handleMsgIconClick)

/** Checks if the username is formated correctly and available.
 * 
 * @param {HTMLElement} inputGroup - The input group element containing the username input field.
 * @param {string} username - The username to check.
 * @param {boolean} [ignoreEmpty=false] - If true, ignores empty username input and does not show an error message.
 * @returns {Promise<boolean>}
 */
export async function checkUsername(inputGroup, username, ignoreEmpty=false) {
	const queryParams = new URLSearchParams({ username }).toString()

	if (ignoreEmpty && !username) return addMsg(inputGroup, false, '', true, true)

	const response = await fetch(`/api/users/check-username?${queryParams}`, { method: 'GET' })
		.then(response => response.json())

	addMsg(inputGroup, response.passed, response.message, true, true)

	return response.passed
}


///////////////////
/// EMAIL INPUT ///
///////////////////

/** Handles the email input field change event. **/
document.querySelector('#email-input')?.addEventListener('input', async function() {
	const inputGroup = document.querySelector('#email-group')
	const email = this.value.trim()
	await checkEmail(inputGroup, email, true)
})

/** Handles the email group icon click event. **/
document.querySelector('#email-icon')?.addEventListener('click', handleMsgIconClick)

/** Checks if the email is formated correctly and available.
 * 
 * @param {HTMLElement} inputGroup - The input group element containing the email input field.
 * @param {string} email - The email to check.
 * @param {boolean} [ignoreEmpty=false] - If true, ignores empty email input and does not show an error message.
 * @returns {Promise<boolean>}
 */
export async function checkEmail(inputGroup, email, ignoreEmpty=false) {
	const queryParams = new URLSearchParams({ email }).toString()

	if (ignoreEmpty && !email) return addMsg(inputGroup, false, '', true, true)

	const response = await fetch(`/api/users/check-email?${queryParams}`, { method: 'GET' })
		.then(response => response.json())

	addMsg(inputGroup, response.passed, response.message, true, true)

	return response.passed
}


//////////////////////
/// PASSWORD INPUT ///
//////////////////////

/** Handles the password input field change event. */
async function handlePasswordInput() {
	const inputGroup = document.querySelector('#password-group')
	const password = inputGroup.querySelector('#password-input').value
	const confirm = inputGroup.querySelector('#confirm-password-input').value
	await checkPassword(inputGroup, password, confirm, true)
}
document.querySelector('#password-input')?.addEventListener('input', handlePasswordInput)
document.querySelector('#confirm-password-input')?.addEventListener('input', handlePasswordInput)

/** Handles the password group icon click event. **/
document.querySelector('#password-icon')?.addEventListener('click', handleMsgIconClick)

/** Checks if the password is formated correctly and meets the requirements.
 * 
 * @param {HTMLElement} inputGroup - The input group element containing the password input fields.
 * @param {string} password - The password to check.
 * @param {string} confirm - The confirmation password.
 * @param {boolean} [ignoreEmpty=false] - If true, ignores empty password input and does not show an error message.
 * @returns {Promise<boolean>}
 */
export async function checkPassword(inputGroup, password, confirm, ignoreEmpty=false) {
	const queryParams = new URLSearchParams({ password, confirm, getAllErrors: true }).toString()

	if (ignoreEmpty && (!password && !confirm)) return addMsg(inputGroup, false, '', true, true)

	const response = await fetch(`/api/users/check-password?${queryParams}`, { method: 'GET' })
		.then(response => response.json())

	if ('requirements' in response.data) {
		addMsg(inputGroup, response.passed, '', true, true)

		Object.values(response.data.requirements).forEach(([passed, message]) => {
			addMsg(inputGroup, passed, message, false, false) 
		})
	} else {
		addMsg(inputGroup, response.passed, response.message, true, true)
	}

	return response.passed
}


///////////////////////
/// FORM SUBMISSION ///
///////////////////////

/** Handles the form submission event. **/
document.querySelector('#register-form')?.addEventListener('submit', async function(e) {
	e.preventDefault()
	
	const username = this.querySelector('#username-input')?.value?.trim()
	const email = this.querySelector('#email-input')?.value?.trim()
	const password = this.querySelector('#password-input')?.value
	const confirm = this.querySelector('#confirm-password-input')?.value

	await register(username, email, password, confirm)
})

/** Registers a new user with the provided username, email, and password. If the registration is successful, it logs the user in.
 * 
 * @param {string} username - The username of the new user.
 * @param {string} email - The email of the new user.
 * @param {string} password - The password of the new user.
 * @param {string} confirm - The confirmation password. 
 */
async function register(username, email, password, confirm) {
	const params = { username, email, password, confirm }

	// Attempt to register the user.
	const response = await fetch('/api/users/register', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(params)
	}).then(response => response.json())

	// If the response failed, display the error messages and focus the input field.
	if (!response.passed) {
		if (response.focus) {
			const input = document.querySelector(`#${response.focus}-input`)
			input?.focus()
			input?.select()
		}

		if (response.id === 200 && response.code === 'user-create') {
			const usernameGroup = document.querySelector('#username-group')
			addMsg(usernameGroup, response.data.username.passed, response.data.username.message, false, true)

			const emailGroup = document.querySelector('#email-group')
			addMsg(emailGroup, response.data.email.passed, response.data.email.message, false, true)

			const passwordGroup = document.querySelector('#password-group')
			if ('requirements' in response.data.password.data) {
				addMsg(passwordGroup, response.data.password.passed, '', true, true)

				Object.values(response.data.password.data.requirements).forEach(([passed, message]) => {
					addMsg(passwordGroup, passed, message, false, false)
				})
			} else {
				addMsg(passwordGroup, response.data.password.passed, response.data.password.message, true, true)
			}
		}

		console.error(response.message) // TODO: make a nice toast error message
		return
	}

	// If the registration was successful, log the user in.
	login(params.username, params.password)
}