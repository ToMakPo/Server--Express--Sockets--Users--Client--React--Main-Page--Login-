import { addMsg } from './utils.js'

///////////////////////
/// UPDATE USERNAME ///
///////////////////////
const { checkUsername } = await import('./register.js')
const updateUsernameModal = document.querySelector('#update-username-modal')

/** Handle username option click event to show the update username modal. **/
document.querySelector('#username-option')?.addEventListener('click', function() {
	if (!updateUsernameModal) return
	updateUsernameModal.querySelector('#update-username-form').reset()
	
	const username = document.querySelector('#username-option .value').innerText
	updateUsernameModal.querySelector('#new-username-input').value = username

	updateUsernameModal.showModal()
})

/** Handle close button click event to close the update username modal. **/
document.querySelector('#update-username-modal .close-button')?.addEventListener('click', function() {
	updateUsernameModal?.close()
})

/** Handle new username input field change event. **/
document.querySelector('#new-username-input')?.addEventListener('input', async function() {
	const inputGroup = document.querySelector('#new-username-group')
	const username = this.value
	await checkUsername(inputGroup, username, true)
})

/** Handle update username form submit event to update the username. **/
document.querySelector('#update-username-form')?.addEventListener('submit', function(event) {
	event.preventDefault()

	const newUsername = this.querySelector('#new-username-input').value.trim()
	const password = this.querySelector('#update-username-password-input').value

	updateUsername(newUsername, password)
})

/** Attempts to update the username. If the update is successful, the modal is closed and the username is updated.
 * 
 * @param {string} newUsername - The new username to update.
 * @param {string} password - The current password of the user.
 */
async function updateUsername(newUsername, password) {
	const response = await fetch('/api/users/update', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ newUsername, password, notes: 'username updated' })
	}).then(response => response.json())

	if (response.passed) {
		document.querySelector('#username-option .value').innerText = newUsername
		document.querySelector('#new-username-input').value = newUsername
		document.querySelector('#page-header-username').innerText = newUsername
		updateUsernameModal.close()
		// TODO: Show success toast message indicating that the username was updated successfully.
	} else {
		const focusId = response.focus === 'currentPassword' ? '#update-username-password-input' : '#new-username-input'

		const focusedInput = document.querySelector(focusId)
		focusedInput.focus()
		focusedInput.select()

		const inputGroup = document.querySelector(`.input-group:has(${focusId})`)
		addMsg(inputGroup, false, response.message, true, true)
		// TODO: Show error toast message indicating that the username update failed.
	}
}

////////////////////
/// UPDATE EMAIL ///
////////////////////
const { checkEmail } = await import('./register.js')
const updateEmailModal = document.querySelector('#update-email-modal')

/** Handle email option click event to show the update email modal. **/
document.querySelector('#email-option')?.addEventListener('click', function() {
	if (!updateEmailModal) return
	updateEmailModal.querySelector('#update-email-form').reset()

	const email = document.querySelector('#email-option .value').innerText
	updateEmailModal.querySelector('#new-email-input').value = email

	updateEmailModal.showModal()
})

/** Handle close button click event to close the update email modal. **/
document.querySelector('#update-email-modal .close-button')?.addEventListener('click', function() {
	updateEmailModal?.close()
})

/** Handle new email input field change event. **/
document.querySelector('#new-email-input')?.addEventListener('input', async function() {
	const inputGroup = document.querySelector('#new-email-group')
	const email = this.value

	await checkEmail(inputGroup, email, true)
})

/** Handle update email form submit event to update the email. **/
document.querySelector('#update-email-form')?.addEventListener('submit', function(event) {
	event.preventDefault()

	const newEmail = this.querySelector('#new-email-input').value.trim()
	const password = this.querySelector('#update-email-password-input').value

	updateEmail(newEmail, password)
})

/** Attempts to update the email. If the update is successful, the modal is closed and the email is updated.
 * 
 * @param {string} newEmail - The new email to update.
 * @param {string} password - The current password of the user.
 */
async function updateEmail(newEmail, password) {
	const response = await fetch('/api/users/update', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ newEmail, password, notes: 'email updated' })
	}).then(response => response.json())

	if (response.passed) {
		document.querySelector('#email-option .value').innerText = newEmail
		updateEmailModal.close()
		// TODO: Send verification email to the new email address.
		// TODO: Show success toast message indicating that the email was updated successfully.
	} else {
		const focusId = response.focus === 'currentPassword' ? '#update-email-password-input' : '#new-email-input'

		const focusedInput = document.querySelector(focusId)
		focusedInput.focus()
		focusedInput.select()

		const inputGroup = document.querySelector(`.input-group:has(${focusId})`)
		addMsg(inputGroup, false, response.message, true, true)
		// TODO: Show error toast message indicating that the email update failed.
	}
}


///////////////////////
/// UPDATE PASSWORD ///
///////////////////////
const { checkPassword } = await import('./register.js')
const updatePasswordModal = document.querySelector('#update-password-modal')

/** Handle password option click event to show the update password modal. **/
document.querySelector('#password-option')?.addEventListener('click', function() {
	updatePasswordModal?.querySelector('#update-password-form').reset()

	updatePasswordModal?.showModal()
})

/** Handle close button click event to close the update password modal. **/
document.querySelector('#update-password-modal .close-button')?.addEventListener('click', function() {
	updatePasswordModal?.close()
})

/** Handle new password input field change event. */
async function handlePasswordInput() {
	const inputGroup = document.querySelector('#new-password-group')
	const password = inputGroup.querySelector('#new-password-input').value
	const confirm = inputGroup.querySelector('#confirm-new-password-input').value
	await checkPassword(inputGroup, password, confirm, true)
}
document.querySelector('#new-password-input')?.addEventListener('input', handlePasswordInput)
document.querySelector('#confirm-new-password-input')?.addEventListener('input', handlePasswordInput)

/** Handle update password form submit event to update the password. **/
document.querySelector('#update-password-form')?.addEventListener('submit', function(event) {
	event.preventDefault()

	const newPassword = this.querySelector('#new-password-input').value
	const confirmPassword = this.querySelector('#confirm-new-password-input').value
	const password = this.querySelector('#update-password-password-input').value

	updatePassword(newPassword, confirmPassword, password)
})

/** Attempts to update the password. If the update is successful, the modal is closed and the password is updated.
 * 
 * @param {string} newPassword - The new password to update.
 * @param {string} confirmPassword - The confirmation password.
 * @param {string} password - The current password of the user.
 */
async function updatePassword(newPassword, confirmPassword, password) {
	const response = await fetch('/api/users/update', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ newPassword, confirmPassword, password, notes: 'password updated' })
	}).then(response => response.json())

	if (response.passed) {
		updatePasswordModal.close()

		// TODO: Show success toast message indicating that the password was updated successfully.
	} else {
		const focusId = response.focus === 'currentPassword' ? '#update-password-password-input' 
			: response.focus === 'confirm-password' ? '#confirm-new-password-input'
			: '#new-password-input'

		const focusedInput = document.querySelector(focusId)
		focusedInput.focus()
		focusedInput.select()

		const inputGroup = document.querySelector(`.input-group:has(${focusId})`)
		if ('requirements' in response.data) {
			addMsg(inputGroup, false, '', true, true)
			
			Object.values(response.data.requirements).forEach(([passed, message]) => {
				addMsg(inputGroup, passed, message, false, false) 
			})
		} else {
			addMsg(inputGroup, false, response.message, true, true)
		}

		// TODO: Show error toast message indicating that the password update failed.
	}
}


//////////////////////
/// DELETE ACCOUNT ///
//////////////////////
const { logout } = await import('./header.js')
const deleteAccountModal = document.querySelector('#delete-account-modal')

/** Handle delete account option click event to show the delete account modal. **/
document.querySelector('#delete-account-button')?.addEventListener('click', function() {
	deleteAccountModal?.querySelector('#delete-account-form').reset()

	deleteAccountModal?.showModal()
})

/** Handle close button click event to close the delete account modal. **/
document.querySelector('#delete-account-modal .close-button')?.addEventListener('click', function() {
	deleteAccountModal?.close()
})

/** Handle delete account form submit event to delete the account. **/
document.querySelector('#delete-account-form')?.addEventListener('submit', function(event) {
	event.preventDefault()

	const password = this.querySelector('#delete-account-password-input').value

	deleteAccount(password)
})

/** Attempts to delete the account. If the deletion is successful, the user is logged out and redirected to the login page.
 * 
 * @param {string} password - The current password of the user.
 */
async function deleteAccount(password) {
	const response = await fetch('/api/users/delete', {
		method: 'DELETE',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password })
	}).then(response => response.json())

	if (response.passed) {
		deleteAccountModal.close()
		logout()

		// TODO: Show success toast message indicating that the account was deleted successfully.
	} else {
		const focusedInput = document.querySelector('#delete-account-password-input')
		focusedInput.focus()
		focusedInput.select()

		const inputGroup = document.querySelector('#delete-account-password-group')
		addMsg(inputGroup, false, response.message, true, true)

		// TODO: Show error toast message indicating that the account deletion failed.
	}
}
