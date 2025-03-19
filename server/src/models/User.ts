import mongoose, { Schema, Document, ObjectId } from 'mongoose'
import { Response as ApiResponse, response as apiResponse } from '../lib/response'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Request, Response, NextFunction } from 'express'

const SECRET_KEY = (process.env.JWT_SECRET as string) || 'default'
const EXPIRATION_TIME = process.env.JWT_EXPIRATION ? parseInt(process.env.JWT_EXPIRATION) : '1h'

interface IUserValues {
	username: string
	email: string
	hash: string
	active: boolean
}
export interface IUser extends Document {
	_id: ObjectId
	username: string
	email: string
	hash: string // hashed password
	active: boolean
	updatedLog: {
		timestamp: Date
		notes: string
		changes: Partial<IUserValues>
	}[]
}

const userValuesSchema: Schema = new Schema(
	{
		username: { type: String },
		email: { type: String },
		hash: { type: String },
		active: { type: Boolean }
	},
	{ _id: false }
)

const userSchema: Schema = new Schema({
	username: { type: String, required: true, unique: true },
	email: { type: String, required: true, unique: true },
	hash: { type: String, required: true },
	active: { type: Boolean, default: true },
	updatedLog: [
		{
			timestamp: { type: Date, default: Date.now },
			notes: { type: String, default: '' },
			changes: { type: userValuesSchema, required: true },
			_id: false
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
	private active: boolean
	private updatedLog: IUser['updatedLog']
	private token: string | null

	private constructor(userModel: IUser) {
		this.id = userModel._id.toString()
		this.username = userModel.username
		this.email = userModel.email
		this.hash = userModel.hash
		this.active = userModel.active
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
	getActive(): boolean {
		return this.active
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

	static async checkUsername(username: string, ignoreId?: string): Promise<ApiResponse> {
		const code = 'user-check-username'

		if (!username) {
			return apiResponse(200, code, false, 'No username provided', username)
		}

		if (username.length < User.MIN_USERNAME_LENGTH) {
			return apiResponse(201, code, false, `Username must be at least ${User.MIN_USERNAME_LENGTH} characters long`, username)
		}

		if (username.length > User.MAX_USERNAME_LENGTH) {
			return apiResponse(202, code, false, `Username must be at most ${User.MAX_USERNAME_LENGTH} characters long`, username)
		}

		if (!/^[a-zA-Z0-9_]+$/.test(username)) {
			return apiResponse(203, code, false, 'Username can only contain letters, numbers, and underscores', username)
		}

		if (username.includes('__')) {
			return apiResponse(204, code, false, 'Username cannot contain consecutive underscores', username)
		}

		if (username.startsWith('_') || username.endsWith('_')) {
			return apiResponse(205, code, false, 'Username cannot start or end with an underscore', username)
		}

		// Check if username is unique.
		const existingUser = await UserModel.findOne({
			username: { $regex: `^${username}$`, $options: 'i' },
			_id: { $ne: ignoreId }, // Ignore the user with the given ID
			active: true // Only check requested username against active users
		})
		if (existingUser) {
			return apiResponse(206, code, false, 'Username is already taken', username)
		}

		return apiResponse(100, code, true, 'Username is valid', username)
	}
	static async checkEmail(email: string, ignoreId?: string): Promise<ApiResponse> {
		const code = 'user-check-email'

		if (!email) {
			return apiResponse(200, code, false, 'No email provided', email)
		}

		if (!User.EMAIL_REGEX.test(email)) {
			return apiResponse(201, code, false, 'Invalid email format', email)
		}

		// Check if email is unique.
		const existingUser = await UserModel.findOne({
			email: { $regex: `^${email}$`, $options: 'i' },
			_id: { $ne: ignoreId } // Ignore the user with the given ID
		})
		if (existingUser) {
			return apiResponse(202, code, false, 'Email is already registered', email)
		}

		return apiResponse(100, code, true, 'Email is valid', email)
	}
	static async checkPassword(password: string, getAllErrors?: boolean): Promise<ApiResponse> {
		const code = 'user-check-password'

		if (!password) {
			return apiResponse(200, code, false, 'No password provided')
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
				? apiResponse(101, code, true, 'Password is valid', requirements)
				: apiResponse(201, code, false, 'Password does not meet requirements', requirements)
		}

		if (password.length < User.MIN_PASSWORD_LENGTH) {
			return apiResponse(201, code, false, `Password must be at least ${User.MIN_PASSWORD_LENGTH} characters long`)
		}

		if (password.length > User.MAX_PASSWORD_LENGTH) {
			return apiResponse(202, code, false, `Password must be at most ${User.MAX_PASSWORD_LENGTH} characters long`)
		}

		if (!/[a-z]/.test(password)) {
			return apiResponse(203, code, false, 'Password must contain at least one lowercase letter')
		}

		if (!/[A-Z]/.test(password)) {
			return apiResponse(204, code, false, 'Password must contain at least one uppercase letter')
		}

		if (!/[0-9]/.test(password)) {
			return apiResponse(205, code, false, 'Password must contain at least one number')
		}

		if (!new RegExp(`[${User.SPECIAL_CHARACTERS}]`).test(password)) {
			return apiResponse(206, code, false, `Password must contain at least one special character (${User.SPECIAL_CHARACTERS})`)
		}

		return apiResponse(100, code, true, 'Password is valid')
	}

	static async create(username: string, email: string, password: string): Promise<ApiResponse> {
		const code = 'user-create'

		const usernameCheck = await User.checkUsername(username)
		if (!usernameCheck.passed) return usernameCheck

		const emailCheck = await User.checkEmail(email)
		if (!emailCheck.passed) return emailCheck

		const passwordCheck = await User.checkPassword(password)
		if (!passwordCheck.passed) return passwordCheck

		// Hash the password
		const hash = await bcrypt.hash(password, 10)
		if (!hash) return apiResponse(200, 'user-create', false, 'Failed to hash password', username)

		// Create the user
		const userModel = new UserModel({
			username,
			email,
			hash,
			updatedLog: [
				{
					timestamp: new Date(),
					notes: 'user created',
					changes: {
						username,
						email,
						hash,
						active: true
					}
				}
			]
		})

		await userModel.save()
		if (!userModel) return apiResponse(201, code, false, 'Failed to create user', [username, email])

		const user = new User(userModel)
		return apiResponse(100, code, true, 'User created successfully', user)
	}

	static async update(
		id: string,
		params: {
			username?: string
			email?: string
			password?: string
			active?: boolean
		},
		notes?: string
	): Promise<ApiResponse> {
		const code = 'user-update'

		const userModel = await UserModel.findById(id)
		if (!userModel) return apiResponse(200, code, false, 'User not found', id)

		const { username, email, password, active } = params
		const changes = {} as Partial<IUserValues>

		if (username && username !== userModel.username) {
			const usernameCheck = await User.checkUsername(username, id)
			if (!usernameCheck.passed) return usernameCheck

			changes['username'] = username
			userModel.username = username
		}

		if (email && email !== userModel.email) {
			const emailCheck = await User.checkEmail(email, id)
			if (!emailCheck.passed) return emailCheck

			changes['email'] = email
			userModel.email = email
		}

		if (password) {
			const passwordCheck = await User.checkPassword(password)
			if (!passwordCheck.passed) return passwordCheck

			// Hash the new password
			const hash = await bcrypt.hash(password, 10)
			if (!hash) return apiResponse(201, code, false, 'Failed to hash password', id)

			changes['hash'] = hash
			userModel.hash = hash
		}

		if (active !== undefined) {
			if (active !== userModel.active) {
				changes['active'] = active
				userModel.active = active
			}
		}

		if (Object.keys.length === 0) {
			return apiResponse(202, code, false, 'No changes made', id)
		}

		// Update the updatedLog
		userModel.updatedLog.push({
			timestamp: new Date(),
			notes: notes || 'User updated',
			changes
		})

		await userModel.save()
		if (!userModel) return apiResponse(203, code, false, 'Failed to update user', id)

		return apiResponse(100, code, true, 'User updated successfully', userModel)
	}

	static async delete(id: string): Promise<ApiResponse> {
		const code = 'user-delete'

		const userModel = await UserModel.findByIdAndDelete(id)
		if (!userModel) return apiResponse(200, code, false, 'User not found', id)

		return apiResponse(100, code, true, 'User deleted successfully', userModel)
	}

	static async login(credentials: string, password: string, ipAddress: string): Promise<ApiResponse> {
		const code = 'user-login'

		if (!credentials) {
			return apiResponse(200, code, false, 'No username or email provided', credentials)
		}

		if (!password) {
			return apiResponse(201, code, false, 'No password provided')
		}

		// Find a user by username or email, case-insensitive
		const userModel = await UserModel.findOne({
			active: true,
			$or: [{ username: { $regex: new RegExp(`^${credentials}$`, 'i') } }, { email: { $regex: new RegExp(`^${credentials}$`, 'i') } }]
		})
		if (!userModel) {
			return apiResponse(202, code, false, 'User not found', credentials)
		}

		// Check if password is correct
		if (!bcrypt.compareSync(password, userModel.hash)) {
			return apiResponse(203, code, false, 'Invalid password')
		}
		await userModel.save()

		const user = new User(userModel)

		const token = User.generateToken(user.getId())
		if (!token) return apiResponse(204, code, false, 'Failed to generate token', user.getId())

		user.token = token

		return apiResponse(100, code, true, 'Login successful', user)
	}

	static async logout(userId: string): Promise<ApiResponse> {
		const code = 'user-logout'

		const userModel = await UserModel.findById(userId)
		return userModel ? apiResponse(100, code, true, 'Logout successful') : apiResponse(200, code, false, 'User not found', userId)
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

	static getToken(req: Request): string | null {
		return req.cookies.token || req.headers.authorization?.split(' ')[1] || null
	}
	/**
	 * Get the time left on the token in seconds.
	 *
	 * @param token The token to get the time left on.
	 * @returns The time left on the token in seconds.
	 */
	static getTokenTimeLeft(token: string): number {
		const decoded = jwt.decode(token) as { exp: number }
		if (!decoded || !decoded.exp) return 0
		return decoded.exp - Math.floor(Date.now() / 1000)
	}

	/** Middleware for routes that require authentication. If the user is not authenticated, it will redirect them to the login page. */
	static async authenticate(req: Request, res: Response, next: NextFunction) {
		const token = User.getToken(req)
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

	/** Middleware that provides the user information if available, but returns null for the user if not available. No redirects. */
	static async getUserInfo(req: Request, res: Response, next: NextFunction) {
		req.body.user = null

		const token = User.getToken(req)
		if (!token) return next()
		const decoded = User.verifyToken(token)
		if (!decoded) return next()

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
			active?: boolean
		},
		notes?: string
	): Promise<ApiResponse> {
		const response = await User.update(this.id, params, notes)

		if (response.passed) {
			const userModel = response.data as IUser
			this.username = userModel.username
			this.email = userModel.email
			this.hash = userModel.hash
			this.active = userModel.active
			this.updatedLog = userModel.updatedLog
		}

		return response
	}

	async delete(force?: boolean): Promise<ApiResponse> {
		// TODO: Check if the user is being referenced by any other documents.
		// if (!force) {
		// 	const code = 'user-delete'

		// 	// If the deletion is being forced, then delete the user. Otherwise, check if the user is being referenced by any other
		// 	// documents. If they are, then instead of deleting the user, just set their active status to false.
		// 	let userReferenced = false

		// 	if (userReferenced) return await this.update({ active: false }, 'User deleted')
		// }

		const response = await User.delete(this.id)

		if (response.passed) {
			this.active = false
			this.token = null
		}

		return response
	}

	async logout(): Promise<ApiResponse> {
		const response = await User.logout(this.id)

		if (response.passed) this.token = null

		return response
	}
}

export default User
