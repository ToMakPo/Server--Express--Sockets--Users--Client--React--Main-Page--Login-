import { Router } from 'express'
import User, { IUser, IUserCreate, IUserUpdateParams, Status } from '../models/User'
import { response as apiResponse } from '../lib/response'

const userRouter = Router()

// Check username
userRouter.get('/check-username', async (req, res) => {
	const username = req.query.username as string
	let ignoreId = req.query.ignoreId as string | undefined

	if (ignoreId === undefined) {
		const token = User.getToken(req)
		const user = await User.findByToken(token)
		if (user) ignoreId = user.id
	}

	const response = await User.checkUsername(username, ignoreId)

	res.json(response)
})

// Check email
userRouter.get('/check-email', async (req, res) => {
	const email = req.query.email as string
	let ignoreId = req.query.ignoreId as string | undefined

	if (ignoreId === undefined) {
		const token = User.getToken(req)
		const user = await User.findByToken(token)
		if (user) ignoreId = user.id
	}

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

	const params = {
		username: req.body.params.username as string | undefined,
		email: req.body.params.email as string | undefined,
		password: req.body.params.password as string | undefined,
		confirm: req.body.params.confirm as string | undefined,
		status: req.body.params.status as Status | undefined,
		preferences: req.body.params.preferences as Partial<IUser['preferences']> | undefined,
		active: req.body.params.active as boolean | undefined,
	} as IUserUpdateParams
	const password = req.body.password as string | undefined
	const notes = req.body.notes as string | undefined

	// Attempt to update the user.
	const response = await user.update(params, password, notes)
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

	const password = (req.body.password as string | undefined) ?? ''
	const force = req.body.force as boolean | undefined
	const notes = req.body.notes as string | undefined

	const response = await user.delete(password, force, notes)
	res.json(response)
})

// Register a new user
userRouter.post('/register', async (req, res) => {
	const params = {
		username: req.body.params.username as string | undefined,
		email: req.body.params.email as string | undefined,
		password: req.body.params.password as string | undefined,
		confirm: req.body.params.confirm as string | undefined,
		status: req.body.params.status as Status | undefined,
		preferences: req.body.params.preferences as Partial<IUser['preferences']> | undefined,
		active: req.body.params.active as boolean | undefined
	} as IUserCreate
	const notes = req.body.notes as string | undefined

	const response = await User.create(params, notes)
	res.json(response)
})

// User login
userRouter.post('/login', async (req, res) => {
	const credentials = (req.body.credentials as string | undefined) ?? ''
	const password = (req.body.password as string | undefined) ?? ''

	const response = await User.login(credentials, password)
	if (response.passed) {
		const { user, token } = response.data
		res.cookie('token', token)
		response.data = { user }
	}
	res.json(response)
})

// User logout
userRouter.post('/logout', User.getInfo, async (req, res) => {
	const code = 'api-user-logout'

	const user = req.body.user as User
	if (user) {
		await user.logout()
	}

	res.clearCookie('token')
	res.json(apiResponse(100, code, true, 'User logged out successfully.'))
})

export default userRouter
