import mongoose, { Schema, Document, ObjectId } from 'mongoose'
import { Response as ApiResponse, response as apiResponse } from '../lib/response'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Request, Response, NextFunction } from 'express'
import { SignOptions } from 'jsonwebtoken'

const SECRET_KEY = process.env.JWT_SECRET || 'default'
const EXPIRATION_TIME = (process.env.JWT_EXPIRATION as SignOptions['expiresIn']) || '1h'

interface IUserValues {
	username: string
	email: string
	hash: string
	active: boolean
}
export interface IUserUpdateProps {
	username?: string
	email?: string
	password?: string
	confirm?: string
	active?: boolean
}
interface IUser extends Document {
	_id: ObjectId
	username: string
	email: string
	hash: string // hashed password
	active: boolean
	updateLog: {
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
	updateLog: [
		{
			timestamp: { type: Date, default: Date.now },
			notes: { type: String, default: '' },
			changes: { type: userValuesSchema, required: true },
			_id: false
		}
	]
})

const UserModel = mongoose.model<IUser>('User', userSchema)

/**
 * A class representing a user profile.
 */
class User {
	private static USER_REQUIERMENTS = {
		minLength: 3, // username must be at least n characters long; null means no limit
		maxLength: 25, // username must be at most n characters long; null means no limit
		maxUpdateFrequency: null // username must be updated at most once every n days; null means no limit
	}
	private static EMAIL_REQUIERMENTS = {
		regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
	}
	private static PASSWORD_REQUIREMENTS = {
		minLength: 8, // password must be at least n characters long; null means no limit
		maxLength: 60, // password must be at most n characters long; null means no limit
		lowercase: true, // password must contain at least one lowercase letter
		uppercase: true, // password must contain at least one uppercase letter
		number: true, // password must contain at least one number
		specialCharacter: true, // password must contain at least one special character,
		characters: ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
		minUpdateFrequency: 90 // password must be updated at most once every n days; null means no limit
	}

	private id: string
	private username: string
	private email: string
	private hash: string
	private active: boolean
	private updateLog: IUser['updateLog']

	private constructor(userModel: IUser) {
		this.id = userModel._id.toString()
		this.username = userModel.username
		this.email = userModel.email
		this.hash = userModel.hash
		this.active = userModel.active
		this.updateLog = userModel.updateLog
	}

	/**
	 * Get the ID of the user.
	 *
	 * @returns The ID of the user.
	 */
	getId(): string {
		return this.id
	}
	/**
	 * Get the username of the user.
	 *
	 * @returns The username of the user.
	 */
	getUsername(): string {
		return this.username
	}
	/**
	 * Get the email of the user.
	 *
	 * @returns The email of the user.
	 */
	getEmail(): string {
		return this.email
	}
	/**
	 * Get the active status of the user.
	 *
	 * Inactive users are not able to log in. A user should be set to inactive instead of being deleted. This way, their data is still
	 * available in the database and they can be reactivated by an admin.
	 *
	 * @returns The active status of the user.
	 */
	getActive(): boolean {
		return this.active
	}
	/**
	 * Get the update log of the user.
	 *
	 * @returns The update log of the user.
	 */
	getUpdateLog(): IUser['updateLog'] {
		return this.updateLog
	}

	/**
	 * Get the user information that can be sent to the client.
	 */
	getData(): Partial<IUserValues> {
		return {
			username: this.username,
			email: this.email,
			active: this.active
		}
	}

	setValues(params: Partial<IUser>) {
		if (params.username !== undefined) this.username = params.username
		if (params.email !== undefined) this.email = params.email
		if (params.hash !== undefined) this.hash = params.hash
		if (params.active !== undefined) this.active = params.active
		if (params.updateLog !== undefined) this.updateLog = params.updateLog

		return this
	}

	/**
	 * Update the user information.
	 *
	 * @param params The user information to update.
	 * - username: The new username.
	 * - email: The new email.
	 * - password: The new password.
	 * - confirm: The string used to confirm the password was entered correctly.
	 * - active: The new active status.
	 * @param notes The notes to add to the updateLog.
	 * @returns The response from the API.
	 */
	async update(params: Partial<IUserUpdateProps>, notes?: string): Promise<ApiResponse> {
		const response = await User.update(this.id, params, notes)

		if (response.passed) {
			const userModel = response.data as IUser
			this.setValues(userModel)
		}

		return response
	}

	/**
	 * Delete the user.
	 *
	 * @param force If true, the user will be deleted even if they are being referenced by other documents. If false, the user will be
	 * deleted only if they are not being referenced by other documents. Otherwise, the user will be set to inactive instead.
	 * @returns The response from the API.
	 */
	async delete(notes?: string, force?: boolean): Promise<ApiResponse> {
		const response = await User.delete(this.id, notes, force)

		if (response.passed) this.active = false

		return response
	}

	/**
	 * Check if the password matches the user's password.
	 *
	 * @param password The password to check.
	 * @returns True if the password matches, otherwise false.
	 */
	confirmPassword(password: string): boolean {
		return User.confirmPassword(password, this.hash)
	}

	/**
	 * Log the user out.
	 * @returns The response from the API.
	 */
	async logout(): Promise<ApiResponse> {
		return await User.logout(this.id)
	}

	/**
	 * Find the user by ID.
	 *
	 * @param id The ID of the user to find.
	 * @returns The user if found, otherwise null.
	 */
	static async findById(id: string): Promise<User | null> {
		const userModel = await UserModel.findById(id)
		if (!userModel) {
			return null
		}
		return new User(userModel)
	}
	/**
	 * Find the user by username.
	 *
	 * @param username The username to find the user by.
	 * @returns The user if found, otherwise null.
	 * @note This method is case-insensitive.
	 */
	static async findByUsername(username: string): Promise<User | null> {
		const userModel = await UserModel.findOne({
			username: { $regex: `^${username}$`, $options: 'i' }
		})

		return userModel ? new User(userModel) : null
	}
	/**
	 * Find the user by email.
	 *
	 * @param email The email to find the user by.
	 * @returns The user if found, otherwise null.
	 * @note This method is case-insensitive.
	 */
	static async findByEmail(email: string): Promise<User | null> {
		const userModel = await UserModel.findOne({
			email: { $regex: `^${email}$`, $options: 'i' }
		})

		return userModel ? new User(userModel) : null
	}
	/**
	 * Find the user by token.
	 *
	 * @param token The token to find the user by.
	 * @returns The user if found, otherwise null.
	 */
	static async findByToken(token: string | null): Promise<User | null> {
		const decoded = User.verifyToken(token)
		if (!decoded) return null

		// Find the user by ID
		const userId = typeof decoded === 'string' ? decoded : decoded.userId
		return await User.findById(userId)
	}

	/** Get the user information that can be sent to the client.
	 * 
	 * @param user The user to get the data from.
	 * @returns The user data.
	 */
	static getData(user: User | Partial<IUser>): Partial<IUserValues> {
		if (user instanceof User) return user.getData()
		return {
			username: user.username,
			email: user.email,
			active: user.active
		}
	} 

	/**
	 * Check if the username meets the requirements.
	 *
	 * @param username The username to check.
	 * @param ignoreId If provided, the user with this ID will be ignored when checking for existing users with the same username.
	 * @returns The response from the API.
	 */
	static async checkUsername(username: string, ignoreId?: string): Promise<ApiResponse> {
		const code = 'user-check-username'

		if (!username) {
			return apiResponse(200, code, false, 'No username provided', username, 'username')
		}

		if (User.USER_REQUIERMENTS.minLength && username.length < User.USER_REQUIERMENTS.minLength) {
			const msg = `Username must be at least ${User.USER_REQUIERMENTS.minLength} characters long`
			return apiResponse(201, code, false, msg, username, 'username')
		}

		if (User.USER_REQUIERMENTS.maxLength && username.length > User.USER_REQUIERMENTS.maxLength) {
			const msg = `Username must be at most ${User.USER_REQUIERMENTS.maxLength} characters long`
			return apiResponse(202, code, false, msg, username, 'username')
		}

		if (!/^[a-zA-Z0-9_]+$/.test(username)) {
			const msg = 'Username can only contain letters, numbers, and underscores'
			return apiResponse(203, code, false, msg, username, 'username')
		}

		if (username.includes('__')) {
			const msg = 'Username cannot contain consecutive underscores'
			return apiResponse(204, code, false, msg, username, 'username')
		}

		if (username.startsWith('_') || username.endsWith('_')) {
			const msg = 'Username cannot start or end with an underscore'
			return apiResponse(205, code, false, msg, username, 'username')
		}

		// Check if username is unique.
		const existingUser = await UserModel.findOne({
			username: { $regex: `^${username}$`, $options: 'i' },
			_id: { $ne: ignoreId }, // Ignore the user with the given ID
			active: true // Only check requested username against active users
		})
		if (existingUser) {
			const msg = 'Username is already taken'
			return apiResponse(206, code, false, msg, username, 'username')
		}

		return apiResponse(100, code, true, 'Username is valid', username)
	}
	/**
	 * Check if the email meets the requirements.
	 *
	 * @param email The email to check.
	 * @param ignoreId If provided, the user with this ID will be ignored when checking for existing users with the same email.
	 * @returns The response from the API.
	 */
	static async checkEmail(email: string, ignoreId?: string): Promise<ApiResponse> {
		const code = 'user-check-email'

		if (!email) {
			return apiResponse(200, code, false, 'No email provided', email, 'email')
		}

		if (!User.EMAIL_REQUIERMENTS.regex.test(email)) {
			return apiResponse(201, code, false, 'Invalid email format', email, 'email')
		}

		// Check if email is unique.
		const existingUser = await UserModel.findOne({
			email: { $regex: `^${email}$`, $options: 'i' },
			_id: { $ne: ignoreId } // Ignore the user with the given ID
		})
		if (existingUser) {
			return apiResponse(202, code, false, 'Email is already registered', email, 'email')
		}

		return apiResponse(100, code, true, 'Email is valid', email)
	}
	/**
	 * Check if the password meets the requirements.
	 *
	 * @param password The password to check.
	 * @param getAllErrors If true, return all errors. If false, return the first error.
	 * @returns The response from the API.
	 */
	static async checkPassword(password: string, confirm?: string, getAllErrors?: boolean): Promise<ApiResponse> {
		const code = 'user-check-password'

		if (getAllErrors) {
			const requirements = {} as { [any: string]: [boolean, string] }

			if (User.PASSWORD_REQUIREMENTS.minLength && User.PASSWORD_REQUIREMENTS.maxLength) {
				requirements.length = [
					password.length >= User.PASSWORD_REQUIREMENTS.minLength && password.length <= User.PASSWORD_REQUIREMENTS.maxLength,
					`Password must be between ${User.PASSWORD_REQUIREMENTS.minLength} and ${User.PASSWORD_REQUIREMENTS.maxLength} characters long`
				]
			} else if (User.PASSWORD_REQUIREMENTS.minLength) {
				requirements.length = [
					password.length >= User.PASSWORD_REQUIREMENTS.minLength,
					`Password must be at least ${User.PASSWORD_REQUIREMENTS.minLength} characters long`
				]
			} else if (User.PASSWORD_REQUIREMENTS.maxLength) {
				requirements.length = [
					password.length <= User.PASSWORD_REQUIREMENTS.maxLength,
					`Password must be at most ${User.PASSWORD_REQUIREMENTS.maxLength} characters long`
				]
			}

			if (User.PASSWORD_REQUIREMENTS.lowercase) {
				requirements.hasLowercase = [/[a-z]/.test(password), 'Password must contain at least one lowercase letter']
			}

			if (User.PASSWORD_REQUIREMENTS.uppercase) {
				requirements.hasUppercase = [/[A-Z]/.test(password), 'Password must contain at least one uppercase letter']
			}

			if (User.PASSWORD_REQUIREMENTS.number) {
				requirements.hasNumber = [/[0-9]/.test(password), 'Password must contain at least one number']
			}

			if (User.PASSWORD_REQUIREMENTS.specialCharacter) {
				requirements.hasSpecialCharacter = [
					new RegExp(`[${User.PASSWORD_REQUIREMENTS.characters}]`).test(password),
					`Password must contain at least one special character (${User.PASSWORD_REQUIREMENTS.characters})`
				]
			}

			if (confirm !== undefined) {
				requirements.match = [password === confirm, 'The confirmation password must match the provided password']
			}

			const passed = Object.values(requirements).every(([isValid]) => isValid)

			const focus = (() => {
				for (const [key, [passed]] of Object.entries(requirements)) {
					if (!passed) return key === 'match' ? 'confirm-password' : 'password'
				}
				return undefined
			})()

			return passed
				? apiResponse(101, code, true, 'Password is valid', { requirements })
				: apiResponse(201, code, false, 'Password does not meet requirements', { requirements }, focus)
		}

		if (!password) {
			const msg = 'No password provided'
			return apiResponse(200, code, false, msg, null, 'password')
		}

		if (password.length < User.PASSWORD_REQUIREMENTS.minLength) {
			const msg = `Password must be at least ${User.PASSWORD_REQUIREMENTS.minLength} characters long`
			return apiResponse(202, code, false, msg, null, 'password')
		}

		if (password.length > User.PASSWORD_REQUIREMENTS.maxLength) {
			const msg = `Password must be at most ${User.PASSWORD_REQUIREMENTS.maxLength} characters long`
			return apiResponse(203, code, false, msg, null, 'password')
		}

		if (User.PASSWORD_REQUIREMENTS.lowercase && !/[a-z]/.test(password)) {
			const msg = 'Password must contain at least one lowercase letter'
			return apiResponse(204, code, false, msg, null, 'password')
		}

		if (User.PASSWORD_REQUIREMENTS.uppercase && !/[A-Z]/.test(password)) {
			const msg = 'Password must contain at least one uppercase letter'
			return apiResponse(205, code, false, msg, null, 'password')
		}

		if (User.PASSWORD_REQUIREMENTS.number && !/[0-9]/.test(password)) {
			const msg = 'Password must contain at least one number'
			return apiResponse(206, code, false, msg, null, 'password')
		}

		if (User.PASSWORD_REQUIREMENTS.specialCharacter && !new RegExp(`[${User.PASSWORD_REQUIREMENTS.characters}]`).test(password)) {
			const msg = `Password must contain at least one special character (${User.PASSWORD_REQUIREMENTS.characters})`
			return apiResponse(207, code, false, msg, null, 'password')
		}

		if (confirm && password !== confirm) {
			const msg = 'Passwords do not match'
			return apiResponse(208, code, false, msg, null, 'confirm-password')
		}

		return apiResponse(100, code, true, 'Password is valid')
	}

	/**
	 * Create a new user.
	 *
	 * @param username A unique username for the user.
	 * @param email The email address of the user.
	 * @param password The password for the user.
	 * @param confirm The string used to confirm the password was entered correctly.
	 * @returns The response from the API.
	 */
	static async create(username: string, email: string, password: string, confirm?: string): Promise<ApiResponse> {
		const code = 'user-create'

		const response = apiResponse(200, code, true, 'Failed to create user', {}, 'username')

		const usernameCheck = await User.checkUsername(username)
		response.data.username = usernameCheck
		if (!usernameCheck.passed && response.passed) {
			response.passed = false
			response.focus = 'username'
		}

		const emailCheck = await User.checkEmail(email)
		response.data.email = emailCheck
		if (!emailCheck.passed && response.passed) {
			response.passed = false
			response.focus = 'email'
		}

		const passwordCheck = await User.checkPassword(password, confirm, true)
		response.data.password = passwordCheck
		if (!passwordCheck.passed && response.passed) {
			response.passed = false
			response.focus = passwordCheck.focus
		}

		if (!response.passed) return response

		// Hash the password
		const hash = await bcrypt.hash(password, 10)
		if (!hash) return apiResponse(201, code, false, 'Failed to hash password', null, 'password')

		// Create the user
		const userModel = new UserModel({
			username,
			email,
			hash,
			updateLog: [
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
		if (!userModel) return apiResponse(202, code, false, 'Failed to create user', [username, email], 'username')

		// TODO: Send a verification email to the user to confirm their email address before fully activating the account.

		return apiResponse(100, code, true, 'User created successfully', User.getData(userModel))
	}

	/**
	 * Update the user information.
	 *
	 * @param id The ID of the user to update.
	 * @param params The user information to update.
	 * - username: The new username.
	 * - email: The new email.
	 * - password: The new password.
	 * - confirm: The string used to confirm the password was entered correctly.
	 * - active: The new active status.
	 * @param notes The notes to add to the updateLog.
	 * @returns The response from the API.
	 */
	static async update(id: string, params: Partial<IUserUpdateProps>, notes?: string): Promise<ApiResponse> {
		const code = 'user-update'

		const userModel = await UserModel.findById(id)
		if (!userModel) return apiResponse(200, code, false, 'User not found', id)

		const { username, email, password, confirm, active } = params
		const changes = {} as Partial<IUserValues>

		if (username && username !== userModel.username) {
			// Check if the username was updated within the max update frequency
			if (this.USER_REQUIERMENTS.maxUpdateFrequency) {
				let lastUpdate = null

				for (let i = userModel.updateLog.length - 1; i >= 0; i--) {
					const logEntry = userModel.updateLog[i]
					if ('username' in logEntry.changes) {
						lastUpdate = logEntry.timestamp
						break
					}
				}

				if (lastUpdate) {
					const timeSinceLastUpdate = (new Date().getTime() - lastUpdate.getTime()) / (1000 * 60 * 60 * 24) // in days
					if (timeSinceLastUpdate < this.USER_REQUIERMENTS.maxUpdateFrequency) {
						const msg = `Username can only be updated once every ${this.USER_REQUIERMENTS.maxUpdateFrequency} days`
						return apiResponse(207, code, false, msg, username, 'username')
					}
				}
			}

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
			const passwordCheck = await User.checkPassword(password, confirm, true)
			if (!passwordCheck.passed) return passwordCheck

			// Hash the new password
			const hash = await bcrypt.hash(password, 10)
			if (!hash) return apiResponse(201, code, false, 'Failed to hash password')

			changes['hash'] = hash
			userModel.hash = hash
		}

		if (active !== undefined && active !== userModel.active) {
			changes['active'] = active
			userModel.active = active
		}

		if (Object.keys(changes).length === 0) {
			return apiResponse(202, code, false, 'No changes made', id)
		}

		// TODO: If the user is updating their email, send a verification email to confirm the new email address before updating the email
		// address in the database. This will prevent email spoofing and ensure that the user has access to the new email address.

		// Update the updateLog
		userModel.updateLog.push({
			timestamp: new Date(),
			notes: notes || 'user updated',
			changes
		})

		await userModel.save()
		if (!userModel) return apiResponse(203, code, false, 'Failed to update user')

		const msg = 'active' in changes ? `User ${active ? 'activated' : 'deactivated'} successfully` : 'User updated successfully'

		return apiResponse(100, code, true, msg, User.getData(userModel))
	}

	/**
	 * Delete the user.
	 *
	 * @param id The ID of the user to delete.
	 * @param notes The notes to add to the updateLog.
	 * @param force If true, the user will be deleted even if they are being referenced by other documents. If false, the user will be
	 * deleted only if they are not being referenced by other documents. Otherwise, the user will be set to inactive instead.
	 * @returns The response from the API.
	 */
	static async delete(id: string, notes?: string, force?: boolean): Promise<ApiResponse> {
		const code = 'user-delete'

		// TODO: Check if the user is being referenced by any other documents.
		// if (!force) {
		// 	const code = 'user-delete'

		// 	// If the deletion is being forced, then delete the user. Otherwise, check if the user is being referenced by any other
		// 	// documents. If they are, then instead of deleting the user, just set their active status to false.
		// 	// eslint-disable-next-line prefer-const
		// 	let userReferenced = false

		// 	if (userReferenced) {
		// 		return await this.update(id, { active: false }, notes ?? 'User deleted')
		// 	}
		// }
		// const userModel = await UserModel.findById(id)
		const userModel = await UserModel.findByIdAndDelete(id)
		if (!userModel) return apiResponse(200, code, false, 'User not found')

		return apiResponse(100, code, true, 'User deleted successfully', User.getData(userModel))
	}

	/**
	 * Log the user in.
	 *
	 * @param credentials The username or email of the user.
	 * @param password The password of the user.
	 * @returns The response from the API.
	 */
	static async login(credentials: string, password: string): Promise<ApiResponse> {
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
		if (!User.confirmPassword(password, userModel.hash)) {
			return apiResponse(203, code, false, 'Invalid password')
		}
		await userModel.save()

		const userData = User.getData(userModel)

		const token = User.generateToken(userModel._id.toString())
		if (!token) return apiResponse(204, code, false, 'Failed to generate token', userData)

		return apiResponse(100, code, true, 'Login successful', { user: userData, token })
	}

	/**
	 * Log the user out.
	 *
	 * @param userId The ID of the user to log out.
	 * @returns The response from the API.
	 */
	static async logout(userId: string): Promise<ApiResponse> {
		const code = 'user-logout'

		const userModel = await UserModel.findById(userId)
		return userModel 
			? apiResponse(100, code, true, 'Logout successful', User.getData(userModel)) 
			: apiResponse(200, code, false, 'User not found')
	}

	/**
	 * Confirm if the provided password matches the hashed password.
	 *
	 * @param password The password to confirm.
	 * @param hash The hashed password to compare against.
	 * @returns True if the password matches, otherwise false.
	 */
	static confirmPassword(password: string, hash: string): boolean {
		return bcrypt.compareSync(password, hash)
	}

	/**
	 * Generate a token for the user.
	 *
	 * @param userId The ID of the user to generate the token for.
	 * @returns The generated token.
	 */
	private static generateToken(userId: string): string {
		return jwt.sign({ userId }, SECRET_KEY, { expiresIn: EXPIRATION_TIME })
		// Note: The token will be valid for the duration specified in EXPIRATION_TIME.
	}

	/**
	 * Verify the token and return the decoded token if valid, otherwise null.
	 *
	 * @param token The token to verify.
	 * @returns The decoded token if valid, otherwise null.
	 */
	private static verifyToken(token: string | null) {
		if (!token) return null
		try {
			return jwt.verify(token, SECRET_KEY)
		} catch (error) {
			return null
		}
	}

	/**
	 * Get the token from the request. The token can be in the cookies or in the Authorization header.
	 *
	 * @param req The request object.
	 * @returns The token if found, otherwise null.
	 */
	static getToken(req: Request): string | null {
		return req.cookies?.token || req.headers?.authorization?.split(' ')[1] || null
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
	static async getInfo(req: Request, res: Response, next: NextFunction) {
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
}

export default User
