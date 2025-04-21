import { Router } from 'express'
import User, { IUserUpdateProps } from '../models/User'
import { response as apiResponse } from '../lib/response'

const userRouter = Router()

// Check username
userRouter.get('/check-username', async (req, res) => {
	const username = req.query.username as string
	let ignoreId = req.query.ignoreId as string | undefined

	const token = User.getToken(req)
	const user = await User.findByToken(token)
	if (token) {
		if (user && ignoreId === undefined) {
			ignoreId = user.getId()
		}
	}

	const response = await User.checkUsername(username, ignoreId)

	res.json(response)
})

// Check email
userRouter.get('/check-email', async (req, res) => {
	const email = req.query.email as string
	const ignoreId = req.query.ignoreId as string | undefined

	const response = await User.checkEmail(email, ignoreId)

	res.json(response)
})

// Check password
userRouter.get('/check-password', async (req, res) => {
	const password = req.query.password as string
	const confirm = req.query.confirm as string | undefined
	const getAllErrors = req.query.getAllErrors as boolean | undefined

	const response = await User.checkPassword(password, confirm, getAllErrors)

	res.json(response)
})

// Update a user
userRouter.put('/update', User.getInfo, async (req, res) => {
	const code = 'api-user-update'

	const user = req.body.user as User
	if (!user) {
		res.json(apiResponse(200, code, false, 'No user found.'))
		return
	}

	const id = user.getId()
	const newUsername = req.body.newUsername as string | undefined
	const newEmail = req.body.newEmail as string | undefined
	const newPassword = req.body.newPassword as string | undefined
	const newConfirm = req.body.newConfirm as string | undefined
	const password = (req.body.password as string | undefined) || ''
	const notes = (req.body.notes as string | undefined) || 'Updated user'

	const props: Partial<IUserUpdateProps> = {}

	if (newUsername !== undefined && newUsername !== user.getUsername()) props.username = newUsername
	if (newEmail !== undefined && newEmail !== user.getEmail()) props.email = newEmail
	if (newPassword !== undefined) props.password = newPassword
	if (newConfirm !== undefined) props.confirm = newConfirm

	const requirePassword = ['username', 'email', 'password'].some(key => key in props)

	// Validate the current password before updating the user
	if (requirePassword && (!password || !user.confirmPassword(password))) {
		res.json(
			apiResponse(201, code, false, 'You must provide the current password when updating your account.', {}, 'currentPassword')
		)
		return
	}

	const response = await User.update(id, props, notes)

	res.json(response)
})

// Delete a user
userRouter.delete('/delete', User.getInfo, async (req, res) => {
	const code = 'api-user-delete'
	
	const user = req.body.user as User
	if (!user) {
		res.json(apiResponse(200, code, false, 'No user found.'))
		return
	}

	const id = user.getId()
	const password = (req.body.password as string | undefined) || ''
	const notes = (req.body.notes as string | undefined) || 'user deleted'

	const requirePassword = true

	// Validate the current password before updating the user
	if (requirePassword && (!password || !user.confirmPassword(password))) {
		res.json(
			apiResponse(201, code, false, 'You must provide the current password when updating your account.', {}, 'currentPassword')
		)
		return
	}

	const response = await User.delete(id, notes)

	res.json(response)
})

// Register a new user
userRouter.post('/register', async (req, res) => {
	const username = (req.body.username as string | undefined) ?? ''
	const email = (req.body.email as string | undefined) ?? ''
	const password = (req.body.password as string | undefined) ?? ''
	const confirm = (req.body.confirm as string | undefined) ?? ''

	const registerResponse = await User.create(username, email, password, confirm)

	res.json(registerResponse)
})

// User login
/**
 * This function handles user login.
 *
 * @param credentials Username or email of the user
 * @param password Password of the user
 */
userRouter.post('/login', async (req, res) => {
	const { credentials, password } = req.body

	const response = await User.login(credentials, password)

	if (response.passed) {
		res.cookie('token', response.data.token, { httpOnly: true, secure: true, sameSite: 'strict' })
	} else {
		res.clearCookie('token')
	}

	res.json(response)
})

// User logout
userRouter.post('/logout', User.getInfo, async (req, res) => {
	const code = 'api-user-logout'
	if (req.body.user) {
		const userId = req.body.user.id
		await User.logout(userId)
	}

	res.clearCookie('token')
	res.json(apiResponse(100, code, true, 'User logged out successfully.'))
})

export default userRouter
