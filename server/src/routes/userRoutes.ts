import { Router } from "express"
import User from "../models/User"

const router = Router()

// Check username
router.get('/api/users/check-username', async (req, res) => {
	const { username, ignoreId } = req.query

	const result = await User.checkUsername(username as string, ignoreId as string)
	
	return res.status(result.passed ? 200 : 400).json(result)
})

// Check email
router.get('/api/users/check-email', async (req, res) => {
	const { email, ignoreId } = req.query

	const response = await User.checkEmail(email as string, ignoreId as string)
	
	return res.status(response.passed ? 200 : 400).json(response)
})

// Check password
router.get('/api/users/check-password', async (req, res) => {
	const { password, getAllErrors } = req.query

	const response = await User.checkPassword(password as string, getAllErrors === 'true')
	
	return res.status(response.passed ? 200 : 400).json(response)
})

// Create a new user
router.post('/api/users', async (req, res) => {
	const { username, email, password } = req.body

	const response = await User.create(username, email, password)

	res.status(response.passed ? 200 : 400).json(response)
})

// Update a user
router.put('/api/users/:id', User.authenticate, async (req, res) => {
	const { id } = req.params
	const { username, email, password, notes } = req.body

	const response = await User.update(id, {username, email, password}, notes)

	res.status(response.passed ? 200 : 400).json(response)
})

// Delete a user
router.delete('/api/users/:id', User.authenticate, async (req, res) => {
	const { id } = req.params

	const response = await User.delete(id)

	res.status(response.passed ? 200 : 400).json(response)
})

// User login
/**
 * This function handles user login.
 * 
 * @param credentials Username or email of the user
 * @param password Password of the user
 * @param ipAddress IP address of the user
 */
router.post('/api/users/login', async (req, res) => {
	const { credentials, password, ipAddress } = req.body

	const response = await User.login(credentials, password, ipAddress)
	
	return res.status(response.passed ? 200 : 400).json(response)
})

// User logout
router.post('/api/users/logout', User.authenticate, async (req, res) => {
	const { userId, sessionId } = req.body

	const response = await User.logout(userId, sessionId)

	return res.status(response.passed ? 200 : 400).json(response)
})

router.post('/api/users/logout-all', User.authenticate, async (req, res) => {
	const { userId } = req.body

	const response = await User.logoutAll(userId)

	return res.status(response.passed ? 200 : 400).json(response)
})

