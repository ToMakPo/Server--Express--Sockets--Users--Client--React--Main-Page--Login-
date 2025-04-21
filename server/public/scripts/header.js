////////////////////
/// PROFILE MENU ///
////////////////////

/** Handle username click event to toggle profile options menu. **/
document.querySelector('#page-header-username')?.addEventListener('click', () => {
	document.getElementById('profile-options').classList.toggle('show')
})

//////////////
/// LOGOUT ///
//////////////

/** Handle logout button click event. **/
document.querySelector('#logout-button')?.addEventListener('click', async function(e) {
	e.preventDefault()

	await logout()
})

/** Logs the user out. */
export async function logout() {
	const responce = await fetch('/api/users/logout', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' }
	}).then(res => res.json())

	if (responce.passed) {
		window.location.href = '/'
	} else {
		alert(responce.message) // TODO: make a nice error message
	}
}
