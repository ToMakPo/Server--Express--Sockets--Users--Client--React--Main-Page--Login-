import mongoose, { Schema, Document, ObjectId } from 'mongoose'
import { Response, response } from '../lib/response'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Request, Response as expResponse, NextFunction } from 'express'

const SECRET_KEY = (process.env.JWT_SECRET as string) || 'default'
const EXPIRATION_TIME = process.env.JWT_EXPIRATION ? parseInt(process.env.JWT_EXPIRATION) : '1h'

export interface IUser extends Document {
	_id: ObjectId
	username: string
	email: string
	hash: string // hashed password
	updatedLog: {
		timestamp: Date
		notes: string
		changes: {
			field: string
			oldValue: string
			newValue: string
		}[]
	}[]
}

const userSchema: Schema = new Schema({
	username: { type: String, required: true, unique: true },
	email: { type: String, required: true, unique: true },
	hash: { type: String, required: true },
	updatedLog: [
		{
			timestamp: { type: Date, default: Date.now },
			notes: { type: String, default: '' },
			changes: [
				{
					field: { type: String, required: true },
					oldValue: { type: String },
					newValue: { type: String, required: true }
				}
			]
		}
	]
})

const UserModel = mongoose.model<IUser>('User', userSchema)

class User {
	private static MIN_USERNAME_LENGTH = 3
	private static MAX_USERNAME_LENGTH = 20
	private static EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
	private static MAX_PASSWORD_LENGTH = 60
	private static MIN_PASSWORD_LENGTH = 8
	private static SPECIAL_CHARACTERS = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

	private id: string
	private username: string
	private email: string
	private hash: string
	private updatedLog: IUser['updatedLog']
	private token: string | null

	private constructor(userModel: IUser) {
		this.id = userModel._id.toString()
		this.username = userModel.username
		this.email = userModel.email
		this.hash = userModel.hash
		this.updatedLog = userModel.updatedLog
		this.token = null
	}

	getId(): string {
		return this.id
	}

	getUsername(): string {
		return this.username
	}
	getEmail(): string {
		return this.email
	}
	getUpdatedLog(): IUser['updatedLog'] {
		return this.updatedLog
	}

	static async findById(id: string): Promise<User | null> {
		const userModel = await UserModel.findById(id)
		if (!userModel) {
			return null
		}
		return new User(userModel)
	}
	static async findByUsername(username: string, fuzzySearch: boolean): Promise<User | null> {
		if (!fuzzySearch) {
			// Exact match search
			const userModel = await UserModel.findOne({
				username: { $regex: `^${username}$`, $options: 'i' }
			})

			return userModel ? new User(userModel) : null
		} else {
			// Fuzzy search
			const userModels = await UserModel.find({
				username: { $regex: username, $options: 'i' }
			})
			return userModels.length ? new User(userModels[0]) : null
		}
	}
	static async findByEmail(email: string, fuzzySearch: boolean): Promise<User | null> {
		if (!fuzzySearch) {
			// Exact match search
			const userModel = await UserModel.findOne({
				email: { $regex: `^${email}$`, $options: 'i' }
			})

			return userModel ? new User(userModel) : null
		} else {
			// Fuzzy search
			const userModels = await UserModel.find({
				email: { $regex: email, $options: 'i' }
			})
			return userModels.length ? new User(userModels[0]) : null
		}
	}

	static async checkUsername(username: string, ignoreId?: string): Promise<Response> {
		const code = 'user-check-username'

		if (!username) {
			return response(200, code, false, 'No username provided', username)
		}

		if (username.length < User.MIN_USERNAME_LENGTH) {
			return response(201, code, false, `Username must be at least ${User.MIN_USERNAME_LENGTH} characters long`, username)
		}

		if (username.length > User.MAX_USERNAME_LENGTH) {
			return response(202, code, false, `Username must be at most ${User.MAX_USERNAME_LENGTH} characters long`, username)
		}

		if (!/^[a-zA-Z0-9_]+$/.test(username)) {
			return response(203, code, false, 'Username can only contain letters, numbers, and underscores', username)
		}

		if (username.includes('__')) {
			return response(204, code, false, 'Username cannot contain consecutive underscores', username)
		}

		if (username.startsWith('_') || username.endsWith('_')) {
			return response(205, code, false, 'Username cannot start or end with an underscore', username)
		}

		// Check if username is unique.
		const existingUser = await UserModel.findOne({
			username: { $regex: `^${username}$`, $options: 'i' },
			_id: { $ne: ignoreId }
		})
		if (existingUser) {
			return response(206, code, false, 'Username is already taken', username)
		}

		return response(100, code, true, 'Username is valid', username)
	}
	static async checkEmail(email: string, ignoreId?: string): Promise<Response> {
		const code = 'user-check-email'

		if (!email) {
			return response(200, code, false, 'No email provided', email)
		}

		if (!User.EMAIL_REGEX.test(email)) {
			return response(201, code, false, 'Invalid email format', email)
		}

		// Check if email is unique.
		const existingUser = await UserModel.findOne({
			email: { $regex: `^${email}$`, $options: 'i' },
			_id: { $ne: ignoreId }
		})
		if (existingUser) {
			return response(202, code, false, 'Email is already registered', email)
		}

		return response(100, code, true, 'Email is valid', email)
	}
	static async checkPassword(password: string, getAllErrors?: boolean): Promise<Response> {
		const code = 'user-check-password'

		if (!password) {
			return response(200, code, false, 'No password provided')
		}

		if (getAllErrors) {
			const length = password.length >= User.MIN_PASSWORD_LENGTH && password.length <= User.MAX_PASSWORD_LENGTH
			const hasLowercase = /[a-z]/.test(password)
			const hasUppercase = /[A-Z]/.test(password)
			const hasNumber = /[0-9]/.test(password)
			const hasSpecialCharacter = new RegExp(`[${User.SPECIAL_CHARACTERS}]`).test(password)

			const requirements = {
				length: [length, `Password must be between ${User.MIN_PASSWORD_LENGTH} and ${User.MAX_PASSWORD_LENGTH} characters long`],
				hasLowercase: [hasLowercase, 'Password must contain at least one lowercase letter'],
				hasUppercase: [hasUppercase, 'Password must contain at least one uppercase letter'],
				hasNumber: [hasNumber, 'Password must contain at least one number'],
				hasSpecialCharacter: [
					hasSpecialCharacter,
					`Password must contain at least one special character (${User.SPECIAL_CHARACTERS})`
				]
			}

			const passed = Object.values(requirements).every(([isValid]) => isValid)

			return passed
				? response(101, code, true, 'Password is valid', requirements)
				: response(201, code, false, 'Password does not meet requirements', requirements)
		}

		if (password.length < User.MIN_PASSWORD_LENGTH) {
			return response(201, code, false, `Password must be at least ${User.MIN_PASSWORD_LENGTH} characters long`)
		}

		if (password.length > User.MAX_PASSWORD_LENGTH) {
			return response(202, code, false, `Password must be at most ${User.MAX_PASSWORD_LENGTH} characters long`)
		}

		if (!/[a-z]/.test(password)) {
			return response(203, code, false, 'Password must contain at least one lowercase letter')
		}

		if (!/[A-Z]/.test(password)) {
			return response(204, code, false, 'Password must contain at least one uppercase letter')
		}

		if (!/[0-9]/.test(password)) {
			return response(205, code, false, 'Password must contain at least one number')
		}

		if (!new RegExp(`[${User.SPECIAL_CHARACTERS}]`).test(password)) {
			return response(206, code, false, `Password must contain at least one special character (${User.SPECIAL_CHARACTERS})`)
		}

		return response(100, code, true, 'Password is valid')
	}

	static async create(username: string, email: string, password: string): Promise<Response> {
		const code = 'user-create'

		const usernameCheck = await User.checkUsername(username)
		if (!usernameCheck.passed) return usernameCheck

		const emailCheck = await User.checkEmail(email)
		if (!emailCheck.passed) return emailCheck

		const passwordCheck = await User.checkPassword(password)
		if (!passwordCheck.passed) return passwordCheck

		// Hash the password
		const hash = await bcrypt.hash(password, 10)
		if (!hash) return response(200, 'user-create', false, 'Failed to hash password', username)

		// Create the user
		const userModel = new UserModel({
			username,
			email,
			hash,
			updatedLog: [
				{
					timestamp: new Date(),
					notes: 'user created',
					changes: [
						{
							field: 'username',
							oldValue: undefined,
							newValue: username
						},
						{
							field: 'email',
							oldValue: undefined,
							newValue: email
						},
						{
							field: 'hash',
							oldValue: undefined,
							newValue: hash
						}
					]
				}
			]
		})

		await userModel.save()
		if (!userModel) return response(201, code, false, 'Failed to create user', [username, email])

		const user = new User(userModel)
		return response(100, code, true, 'User created successfully', user)
	}

	static async update(
		id: string,
		params: {
			username?: string
			email?: string
			password?: string
		},
		notes?: string
	): Promise<Response> {
		const code = 'user-update'

		const userModel = await UserModel.findById(id)
		if (!userModel) return response(200, code, false, 'User not found', id)

		const { username, email, password } = params
		const changes = []

		if (username && username !== userModel.username) {
			const usernameCheck = await User.checkUsername(username, id)
			if (!usernameCheck.passed) return usernameCheck

			changes.push({ field: 'username', oldValue: userModel.username, newValue: username })
			userModel.username = username
		}

		if (email && email !== userModel.email) {
			const emailCheck = await User.checkEmail(email, id)
			if (!emailCheck.passed) return emailCheck

			changes.push({ field: 'email', oldValue: userModel.email, newValue: email })
			userModel.email = email
		}

		if (password) {
			const passwordCheck = await User.checkPassword(password)
			if (!passwordCheck.passed) return passwordCheck

			// Hash the new password
			const hash = await bcrypt.hash(password, 10)
			if (!hash) return response(201, code, false, 'Failed to hash password', id)

			changes.push({ field: 'hash', oldValue: userModel.hash, newValue: hash })
			userModel.hash = hash
		}

		if (changes.length === 0) {
			return response(202, code, false, 'No changes made', id)
		}

		// Update the updatedLog
		userModel.updatedLog.push({
			timestamp: new Date(),
			notes: notes || 'User updated',
			changes
		})

		await userModel.save()
		if (!userModel) return response(203, code, false, 'Failed to update user', id)

		return response(100, code, true, 'User updated successfully', userModel)
	}

	static async delete(id: string): Promise<Response> {
		const code = 'user-delete'

		const userModel = await UserModel.findByIdAndDelete(id)
		if (!userModel) return response(200, code, false, 'User not found', id)

		return response(100, code, true, 'User deleted successfully', userModel)
	}

	static async login(credentials: string, password: string, ipAddress: string): Promise<Response> {
		const code = 'user-login'

		if (!credentials) {
			return response(200, code, false, 'No username or email provided', credentials)
		}

		if (!password) {
			return response(201, code, false, 'No password provided')
		}

		// Find a user by username or email, case-insensitive
		const userModel = await UserModel.findOne({
			$or: [{ username: { $regex: new RegExp(`^${credentials}$`, 'i') } }, { email: { $regex: new RegExp(`^${credentials}$`, 'i') } }]
		})
		if (!userModel) {
			return response(202, code, false, 'User not found', credentials)
		}

		// Check if password is correct
		if (!bcrypt.compareSync(password, userModel.hash)) {
			return response(203, code, false, 'Invalid password')
		}
		await userModel.save()

		const user = new User(userModel)

		const token = User.generateToken(user.getId())
		if (!token) return response(204, code, false, 'Failed to generate token', user.getId())

		user.token = token

		return response(100, code, true, 'Login successful', user)
	}

	static async logout(userId: string): Promise<Response> {
		const code = 'user-logout'

		const userModel = await UserModel.findById(userId)
		return userModel ? response(100, code, true, 'Logout successful') : response(200, code, false, 'User not found', userId)
	}

	private static generateToken(userId: string): string {
		return jwt.sign({ userId }, SECRET_KEY, { expiresIn: EXPIRATION_TIME })
	}

	private static verifyToken(token: string) {
		try {
			return jwt.verify(token, SECRET_KEY)
		} catch (error) {
			return null
		}
	}

	/** Middleware for routes that require authentication. If the user is not authenticated, it will redirect them to the login page. */
	static async authenticate(req: Request, res: expResponse, next: NextFunction) {
		const token = req.cookies.token || req.headers.authorization?.split(' ')[1] || null
		req.body.user = null

		if (!token) {
			return res.status(401).redirect('/login')
		}

		const decoded = User.verifyToken(token)
		if (!decoded) {
			return res.status(401).redirect('/login')
		}

		// Find the user by ID
		const userId = typeof decoded === 'string' ? decoded : decoded.userId
		const user = await User.findById(userId)

		req.body.user = user
		next()
	}

	/** Middleware explicitly for routes that require you to be logged out. If you are logged in, it will redirect you to the home page. */
	static async dontAuthenticate(req: Request, res: expResponse, next: NextFunction) {
		const token = req.cookies.token || req.headers.authorization?.split(' ')[1] || null
		req.body.user = null

		if (!token) {
			return next()
		}

		const decoded = User.verifyToken(token)
		if (!decoded) {
			return next()
		}
		return res.status(401).redirect('/')
	}

	/** Middleware that provides the user information if available, but returns null for the user if not available. No redirects. */
	static async getUserInfo(req: Request, res: expResponse, next: NextFunction) {
		const token = req.cookies.token || req.headers.authorization?.split(' ')[1] || null
		req.body.user = null
		if (!token) {
			return next()
		}
		const decoded = User.verifyToken(token)
		if (!decoded) {
			return next()
		}
		// Find the user by ID
		const userId = typeof decoded === 'string' ? decoded : decoded.userId
		const user = await User.findById(userId)
		req.body.user = user
		next()
	}

	async update(
		params: {
			username?: string
			email?: string
			password?: string
		},
		notes?: string
	): Promise<Response> {
		const response = await User.update(this.id, params, notes)

		if (response.passed) {
			const userModel = response.data as IUser
			this.username = userModel.username
			this.email = userModel.email
			this.hash = userModel.hash
			this.updatedLog = userModel.updatedLog
		}

		return response
	}

	async delete(): Promise<Response> {
		const response = await User.delete(this.id)

		if (response.passed) {
			this.id = ''
			this.username = ''
			this.email = ''
			this.hash = ''
			this.updatedLog = []
		}

		return response
	}

	async logout(): Promise<Response> {
		const response = await User.logout(this.id)

		if (response.passed) this.token = null

		return response
	}
}

export default User
