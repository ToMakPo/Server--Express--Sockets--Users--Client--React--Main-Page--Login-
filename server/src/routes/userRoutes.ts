import { Router } from 'express'
import User from '../models/User'

const userRouter = Router()

// Check username
userRouter.get('/check-username', async (req, res) => {
	const { username, ignoreId } = req.query

	const response = await User.checkUsername(username as string, ignoreId as string)

	res.status(200).json(response)
})

// Check email
userRouter.get('/check-email', async (req, res) => {
	const { email, ignoreId } = req.query

	const response = await User.checkEmail(email as string, ignoreId as string)

	res.status(200).json(response)
})

// Check password
userRouter.get('/check-password', async (req, res) => {
	const { password, getAllErrors } = req.query

	const response = await User.checkPassword(password as string, getAllErrors === 'true')

	res.status(200).json(response)
})

// Create a new user
userRouter.post('', async (req, res) => {
	const { username, email, password } = req.body

	const response = await User.create(username, email, password)

	res.status(200).json(response)
})

// Update a user
userRouter.put('/:id', User.getUserInfo, async (req, res) => {
	if (req.body.user?.id !== req.params.id) {
		res.status(403).json({ message: 'You can only update your own account.' })
		return
	}

	const { id } = req.params
	const { username, email, password, notes } = req.body

	const response = await User.update(id, { username, email, password }, notes)

	res.status(200).json(response)
})

// Delete a user
userRouter.delete('/:id', User.getUserInfo, async (req, res) => {
	if (req.body.user?.id !== req.params.id) {
		res.status(403).json({ message: 'You can only update your own account.' })
		return
	}

	const { id } = req.params

	const response = await User.delete(id)

	res.status(200).json(response)
})

// Register a new user
userRouter.post('/register', async (req, res) => {
	const { username, email, password, ipAddress } = req.body

	const registerResponse = await User.create(username, email, password)
	if (!registerResponse.passed) {
		res.status(200).json(registerResponse)
		return
	}

	const loginResponse = await User.login(username, password, ipAddress)

	res.status(200).json({ registerResponse, loginResponse })
})

// User login
/**
 * This function handles user login.
 *
 * @param credentials Username or email of the user
 * @param password Password of the user
 * @param ipAddress IP address of the user
 */
userRouter.post('/login', async (req, res) => {
	const { credentials, password, ipAddress } = req.body

	const response = await User.login(credentials, password, ipAddress)

	if (response.passed) {
		const user = response.data
		const token = user.token
		res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' })
	} else {
		res.clearCookie('token')
	}

	res.status(200).json(response)
})

// User logout
userRouter.post('/logout', User.getUserInfo, async (req, res) => {
	if (!req.body.user) {
		res.status(403).json({ message: 'No user found.' })
		return
	}

	const userId = req.body.user.id

	const response = await User.logout(userId)

	if (response.passed) {
		res.clearCookie('token')
		res.status(200).redirect('/')
	} else {
		res.status(200).json(response)
	}
})

export default userRouter
