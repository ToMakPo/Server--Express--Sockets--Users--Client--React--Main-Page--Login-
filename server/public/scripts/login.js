///////////////////////
/// FORM SUBMISSION ///
///////////////////////

/** Handles the form submission event. **/
document.querySelector('#login-form')?.addEventListener('submit', async function(e) {
	e.preventDefault()

	const credentials = document.querySelector('#credentials-input').value.trim()
	const password = document.querySelector('#password-input').value

	await login(credentials, password)
})

/** Logs in a user with the provided credentials and password.
 * 
 * @param {string} credentials 
 * @param {string} password 
 */
export async function login(credentials, password) {
	const params = { credentials, password }

	const responce = await fetch('/api/users/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(params)
	}).then(response => response.json())

	if (responce.passed) {
		window.location.href = '/'
	} else {
		alert(responce.message) // TODO: make a nice error message
	}
}
