import mongoose, { Schema, Document, ObjectId, Types } from 'mongoose'
import { Response as ApiResponse, response as apiResponse } from '../lib/response'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Request, Response, NextFunction } from 'express'
import { SignOptions } from 'jsonwebtoken'
import ChatRoom from './Chat'
import DatabaseModel from './Modal'

const USERNAME_REQUIERMENTS = {
	minLength: 3, // username must be at least n characters long; null means no limit
	maxLength: 25, // username must be at most n characters long; null means no limit
	maxUpdateFrequency: null // username must be updated at most once every n days; null means no limit
}
const EMAIL_REQUIERMENTS = {
	regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
}
const PASSWORD_REQUIREMENTS = {
	minLength: 8, // password must be at least n characters long; null means no limit
	maxLength: 60, // password must be at most n characters long; null means no limit
	lowercase: true, // password must contain at least one lowercase letter
	uppercase: true, // password must contain at least one uppercase letter
	number: true, // password must contain at least one number
	specialCharacter: true, // password must contain at least one special character,
	characters: ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
	minUpdateFrequency: 90, // password must be updated at most once every n days; null means no limit
	reuseLimit: 3 // password must not be the same as the last n passwords; null means no limit
}
const SECRET_KEY = process.env.JWT_SECRET || 'default'
const EXPIRATION_TIME = (process.env.JWT_EXPIRATION as SignOptions['expiresIn']) || '1h'

/** The status of the user.
 * 
 * @enum {string} Status
 * - ***online***: The user is online.
 * - ***offline***: The user is offline.
 * - ***away***: The user is online but away from their device.
 * - ***busy***: The user is online but busy.
 */
export enum Status {
	ONLINE = 'online',
	OFFLINE = 'offline',
	AWAY = 'away',
	BUSY = 'busy'
}

/** The options for the user's perferred theme.
 * 
 * @enum {string} Theme
 * - ***light***: The user prefers a light theme.
 * - ***dark***: The user prefers a dark theme.
 * - ***system***: Use the theme set by the user's operating system.
 */
export enum Theme {
	LIGHT = 'light',
	DARK = 'dark',
	SYSTEM = 'system'
}

/** The user model interface. 
 * 
 * @param id The ID of the user.
 * @param username The username of the user.
 * @param email The email address of the user.
 * @param hash The hashed password of the user.
 * @param status The status of the user. Can be 'online', 'offline', 'away', or 'busy'.
 * @param preferences The preferences of the user.
 * - theme: The theme of the user. Can be 'light', 'dark', or 'system'.
 * @param active The active status of the user. Inactive users are not able to log in.
 * @param updateLog The log of changes made to the user. Each entry contains a timestamp, notes, and the changes made to the user.
*/
export interface IUser {
	id: string
	username: string
	email: string
	hash: string // hashed password
	status: Status
	preferences: {
		theme: Theme
	}
	active: boolean
	updateLog: {
		timestamp: Date
		notes: string
		changes: IUserUpdate
	}[]
}

/** The user model interface that can be sent to the client. */
export interface IUserValues extends Omit<IUser, 'hash' | 'updateLog'> {}

/** The user model interface that can be used to create a new user. */
export interface IUserCreate extends Omit<IUser, 'id' | 'hash' | 'status' | 'preferences' | 'updateLog'> {
	password: string
	confirm?: string
	status?: Status
	preferences?: Partial<IUser['preferences']>
}

/** The user model interface that stores the changes made to the user. */
export interface IUserUpdate extends Partial<Omit<IUser, 'id' | 'preferences' | 'updateLog'>> {
	preferences?: Partial<IUser['preferences']>
}

/** The user model interface that can be used to update the user. */
export interface IUserUpdateParams extends IUserUpdate {
	password?: string
	confirm?: string
}

/** The user schema. */
const userSchema: Schema = new Schema({
	username: { type: String, required: true, unique: true },
	email: { type: String, required: true, unique: true },
	hash: { type: String, required: true },
	status: { type: String, enum: Status, default: 'offline' },
	preferences: {
		theme: { type: String, enum: Theme, default: 'system' }
	},
	active: { type: Boolean, default: true },
	updateLog: [
		{
			timestamp: { type: Date, default: Date.now },
			notes: { type: String, default: '' },
			changes: { 
				type: {
					username: { type: String },
					email: { type: String },
					hash: { type: String },
					preferences: {
						theme: { type: String, enum: Theme }
					},
					active: { type: Boolean }
				},
				required: true
			}
		}
	]
})

/** The user model. */
const UserModel = mongoose.model<IUser>('User', userSchema) 

class User extends DatabaseModel implements IUserValues {
	private model: Document<unknown, {}, IUser> & IUser

	private constructor(model: Document<unknown, {}, IUser> & IUser) {
		super()
		this.model = model
	}

	/// USER ID ///
	/** Get the ID of the user.
	 * 
	 * @returns The ID of the user.
	 */
	get id(): string {
		return this.model.id.toString()
	}

	/// USERNAME ///
	/** Get the username of the user.
	 * 
	 * @returns The username of the user.
	 */
	get username(): string {
		return this.model.username
	}

	/** Check if the username meets the requirements.
	 * 
	 * @param username The username to check.
	 * @returns The response from the API.
	 */
	async checkUsername(username: string): Promise<ApiResponse> {
		const code = 'user-check-username'

		// Check that the new username isn't the same as the current username.
		if (username === this.model.username)
			return apiResponse(200, code, false, 'Username is already set to the provided value', username, 'username')

		// Check that the new username meets the requirements.
		const result = await User.checkUsername(username, this.id)
		if (!result.passed) return result

		// Return the response.
		return apiResponse(100, code, true, 'Username is valid', username)
	}

	/** Set the username of the user.
	 * 
	 * @param username The new username of the user.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	async setUsername(username: string, notes?: string): Promise<ApiResponse> {
		const code = 'user-set-username'

		// Check that the new username meets the requirements.
		const result = await this.checkUsername(username)
		if (!result.passed) return result
		
		// Update the username.
		this.model.username = username

		this.model.updateLog.push({
			timestamp: new Date(),
			notes: notes || 'Username updated',
			changes: { username }
		})
		this.model.save()

		// Return the response.
		return apiResponse(100, code, true, 'Username updated successfully', username)
	}

	/// EMAIL ///
	/** Get the email of the user.
	 * 
	 * @returns The email of the user.
	 */
	get email(): string {
		return this.model.email
	}

	/** Check if the email meets the requirements.
	 * 
	 * @param email The email to check.
	 * @returns The response from the API.
	 */
	async checkEmail(email: string): Promise<ApiResponse> {
		const code = 'user-check-email'

		// Check that the new email isn't the same as the current email.
		if (email === this.model.email)
			return apiResponse(200, code, false, 'Email is already set to the provided value', email, 'email')

		// Check that the new email meets the requirements.
		const result = await User.checkEmail(email, this.id)
		if (!result.passed) return result

		// Return the response.
		return apiResponse(100, code, true, 'Email is valid', email)
	}

	/** Set the email of the user.
	 * 
	 * @param email The new email of the user.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	async setEmail(email: string, notes?: string): Promise<ApiResponse> {
		const code = 'user-set-email'

		// Check that the new email meets the requirements.
		const result = await this.checkEmail(email)
		if (!result.passed) return result

		// Update the email.
		this.model.email = email
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: notes || 'Email updated',
			changes: { email }
		})
		this.model.save()
		
		// Return the response.
		return apiResponse(100, code, true, 'Email updated successfully', email)
	}

	/// PASSWORD ///
	/** Check if the password meets the requirements.
	 * 
	 * @param password The password to check.
	 * @param confirm The string used to confirm the password was entered correctly. (optional)
	 * @param getAllErrors If true, return all errors. If false, return the first error.
	 * @returns The response from the API.
	 */
	async checkPassword(password: string, confirm?: string, getAllErrors?: boolean): Promise<ApiResponse> {
		const code = 'user-check-password'

		// Check that the new password doesn't match the resent passwords.
		const count = Math.max(1, PASSWORD_REQUIREMENTS.reuseLimit)
		for (let i = this.model.updateLog.length - 1, j = 0; i >= 0 && j < count; i--) {
			const hash = this.model.updateLog[i].changes.hash
			if (!hash) continue
			
			if (User.confirmPassword(password, hash)) {
				const msg = count == 1 ? 'Password cannot be the same as the current password' : `Password cannot be the same as the last ${count} passwords`
				return apiResponse(200, code, false, msg, null, 'password')
			}

			j++
		}

		// Check that the new password meets the requirements.
		const result = await User.checkPassword(password, confirm, getAllErrors)
		if (!result.passed) return result

		// Return the response.
		return apiResponse(100, code, true, 'Password is valid')
	}

	/** Get the hashed password of the user.
	 * 
	 * @param password The new password of the user.
	 * @param confirm The string used to confirm the password was entered correctly. (optional)
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The hashed password of the user.
	 */
	async setPassword(password: string, confirm?: string, getAllErrors?: boolean, notes?: string): Promise<ApiResponse> {
		const code = 'user-set-password'

		// Check that the new password meets the requirements.
		const result = await this.checkPassword(password, confirm, getAllErrors)
		if (!result.passed) return result

		// Hash the new password.
		const hash = await bcrypt.hash(password, 10)
		if (!hash) return apiResponse(201, code, false, 'Failed to hash password', null, 'password')

		// Update the password hash.
		this.model.hash = hash
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: notes || 'Password updated',
			changes: { hash }
		})
		this.model.save()

		// Return the response.
		return apiResponse(100, code, true, 'Password updated successfully')
	}

	/** Confirm if the provided password matches the hashed password.
	 * 
	 * @param password The password to confirm.
	 * @returns True if the password matches, otherwise false.
	 */
	async confirmPassword(password: string): Promise<Boolean> {
		return await User.confirmPassword(password, this.model.hash)
	}

	/// STATUS ///
	/** Get the hashed password of the user.
	 * 
	 * @returns The hashed password of the user.
	 */
	get status(): IUser['status'] {
		return this.model.status
	}

	/** Check if the status meets the requirements.
	 * 
	 * @param status The status to check.
	 * @returns The response from the API.
	 */
	async checkStatus(status: IUser['status']): Promise<ApiResponse> {
		const code = 'user-check-status'

		// Check that the new status isn't the same as the current status.
		if (status === this.model.status)
			return apiResponse(200, code, false, 'Status is already set to the provided value', status, 'status')

		// Check that the new status meets the requirements.
		if (!Object.values(Status).includes(status))
			return apiResponse(201, code, false, 'Invalid status', null, 'status')

		// Return the response.
		return apiResponse(100, code, true, 'Status is valid', status)
	}

	/** Set the status of the user.
	 * 
	 * @param status The new status of the user.
	 * @returns The response from the API.
	 */
	async setStatus(status: IUser['status']): Promise<ApiResponse> {
		const code = 'user-set-status'
		
		// Check that the new status meets the requirements.
		const result = await this.checkStatus(status)
		if (!result.passed) return result

		// Update the status.
		this.model.status = status
		this.model.save()

		// Return the response.
		return apiResponse(100, code, true, 'Status updated successfully', status)
	}

	/// PREFERENCES ///
	/** Get the preferences of the user.
	 * 
	 * @returns The preferences of the user.
	 */
	get preferences(): IUser['preferences'] {
		return JSON.parse(JSON.stringify(this.model.preferences))
	}

	get theme(): IUser['preferences']['theme'] {
		return this.model.preferences.theme
	}

	/** Check if the theme meets the requirements.
	 * 
	 * @param theme The theme to check.
	 * @returns The response from the API.
	 */
	async checkTheme(theme: IUser['preferences']['theme']): Promise<ApiResponse> {
		const code = 'user-check-theme'

		// Check that the new theme isn't the same as the current theme.
		if (theme === this.model.preferences.theme)
			return apiResponse(200, code, false, 'Theme is already set to the provided value', theme, 'theme')

		// Check that the new theme meets the requirements.
		if (!Object.values(Theme).includes(theme))
			return apiResponse(201, code, false, 'Invalid theme', null, 'theme')

		// Return the response.
		return apiResponse(100, code, true, 'Theme is valid', theme)
	}

	/** Set the theme of the user.
	 * 
	 * @param theme The new theme of the user.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	async setTheme(theme: IUser['preferences']['theme'], notes?: string): Promise<ApiResponse> {
		const code = 'user-set-theme'

		// Check that the new theme meets the requirements.
		const result = await this.checkTheme(theme)
		if (!result.passed) return result

		// Update the theme.
		this.model.preferences.theme = theme
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: notes || 'Theme updated',
			changes: { preferences: { theme } }
		})
		this.model.save()

		// Return the response.
		return apiResponse(100, code, true, 'Theme updated successfully', theme)
	}

	/// ACTIVE ///
	/** Get the active status of the user.
	 * 
	 * Inactive users are not able to log in. A user should be set to inactive instead of being deleted. This way, their data is still
	 * available in the database and they can be reactivated by an admin.
	 * 
	 * @returns The active status of the user.
	 */
	get active(): boolean {
		return this.model.active
	}

	/** Check if the active status meets the requirements.
	 * 
	 * @param active The active status to check.
	 * @returns The response from the API.
	 */
	async checkActive(active: boolean): Promise<ApiResponse> {
		const code = 'user-check-active'

		// Check that the new active status isn't the same as the current active status.
		if (active === this.model.active)
			return apiResponse(200, code, false, 'Active status is already set to the provided value', active, 'active')

		// Return the response.
		return apiResponse(100, code, true, 'Active status is valid', active)
	}

	/** Set the active status of the user.
	 * 
	 * @param active The new active status of the user.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	async setActive(active: boolean, notes?: string): Promise<ApiResponse> {
		const code = 'user-set-active'

		// Check that the new active status meets the requirements.
		const result = await this.checkActive(active)
		if (!result.passed) return result

		// Update the active status.
		this.model.active = active
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: notes || 'Active status updated',
			changes: { active }
		})
		this.model.save()

		// Return the response.
		return apiResponse(100, code, true, 'Active status updated successfully', active)
	}

	/// VALUES ///
	/** Get the user information that can be sent to the client.
	 * 
	 * @returns The user data.
	 */
	get values(): IUserValues {
		return {
			id: this.id,
			username: this.username,
			email: this.email,
			status: this.status,
			preferences: this.preferences,
			active: this.active
		}
	}

	/** Set the user information.
	 * 
	 * @param params The user information to set. Not all fields are required. Only the fields that are provided will be updated.
	 * - username: Replace the username with the provided value. (Password required)
	 * - email: Replace the email with the provided value. (Password required)
	 * - password: Replace the password with the provided value. (Password required)
	 * - confirm: The string used to confirm the password was entered correctly.
	 * - hash: Replace the password hash with the provided value.
	 * - status: Replace the status with the provided value.
	 * - preferences: Replace all or part of the preferences with the provided values.
	 * - active: Replace the active status with the provided value.
	 * @param password The password of the user. Some fields require the password to be provided in order to be updated.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The updated user instance.
	 */
	async update(params: IUserUpdateParams, password?: string, notes?: string): Promise<ApiResponse> {
		const code = 'user-set-values'

		console.log('Updating user', {params, password, notes})

		// Check that if the new values require a password, the password is provided.
		const requiresPasswordParams = ['username', 'email', 'password']
		const requiresPassword = Object.entries(params).some(([param, value]) => param in requiresPasswordParams)
		console.log('Requires password:', requiresPassword)
		if (requiresPassword) {
			if (!password) {
				const msg = 'Password is required to update the user information'
				return apiResponse(200, code, false, msg, null, 'password')
			}
			const passwordIsValid = await this.confirmPassword(password)
			if (!passwordIsValid) return apiResponse(201, code, false, 'Invalid password', null, 'password')
		}
		
		// Check that the new values meet the requirements.
		if (params.username !== undefined) {
			const result = await this.checkUsername(params.username)
			if (!result.passed) return result
		}

		if (params.email !== undefined) {
			const result = await this.checkEmail(params.email)
			if (!result.passed) return result
		}

		if (params.password !== undefined) {
			const result = await this.checkPassword(params.password, params.confirm, true)
			if (!result.passed) return result
		}

		if (params.status !== undefined) {
			const result = await this.checkStatus(params.status)
			if (!result.passed) return result
		}

		if (params.preferences?.theme !== undefined) {
			const result = await this.checkTheme(params.preferences.theme)
			if (!result.passed) return result
		}

		if (params.active !== undefined) {
			const result = await this.checkActive(params.active)
			if (!result.passed) return result
		}

		// Update the user information.
		const changes: IUserUpdate = {}
		if (params.username !== undefined) {
			this.model.username = params.username
			changes.username = params.username
		}

		if (params.email !== undefined) {
			this.model.email = params.email
			changes.email = params.email
		}

		if (params.password !== undefined) {
			const hash = await bcrypt.hash(params.password, 10)
			if (!hash) return apiResponse(202, code, false, 'Failed to hash password', null, 'password')
			this.model.hash = hash
			changes.hash = hash
		} else
		if (params.hash !== undefined) {
			this.model.hash = params.hash
			changes.hash = params.hash
		}

		if (params.status !== undefined) {
			this.model.status = params.status
		}

		if (params.preferences?.theme !== undefined) {
			this.model.preferences.theme = params.preferences.theme
			if (!changes.preferences) changes.preferences = {}
			changes.preferences.theme = params.preferences.theme
		}

		if (params.active !== undefined) {
			this.model.active = params.active
			changes.active = params.active
		}

		if (Object.keys(changes).length > 0) {
			this.model.updateLog.push({
				timestamp: new Date(),
				notes: notes || 'User updated',
				changes
			})
		}
		this.model.save()

		// Return the response.
		return apiResponse(100, code, true, 'User updated successfully', this.values, notes)
	}

	/// FIND REFERENCES ///
	/** Find all documents that reference the user.
	 * 
	 * @returns A promise that resolves to an object containing the references found. The keys are the names of the models and the values are arrays of documents.
	 */
	async findReferences(): Promise<{ [key: string]: DatabaseModel[] }> {
		const code = 'user-find-references'
		const references = {} as { [key: string]: DatabaseModel[] }

		// Find all chat rooms that the user is a member of.
		const chatRooms = (await ChatRoom.findAllByUserId(this.id)) as ChatRoom[]
		if (chatRooms.length > 0) references.chatRooms = chatRooms

		return references
	}

	/// DELETE ///
	/** Delete the user.
	 * 
	 * @param password The password of the user. This is used to confirm that the user wants to delete their account.
	 * @param force If true, the user will be deleted even if they are being referenced by other documents. If false, the user will be
	 * deleted only if they are not being referenced by other documents. Otherwise, the user will be set to inactive instead.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	async delete(password: string, force?: boolean, notes?: string): Promise<ApiResponse> {
		const code = 'user-delete'

		// Check if the password is correct.
		const passwordIsValid = await this.confirmPassword(password)
		if (!passwordIsValid) return apiResponse(200, code, false, 'Invalid password', null, 'password')

		// Check if the user is being referenced by other documents.
		const references = await this.findReferences()

		const chatRooms = references.chatRooms as ChatRoom[] | undefined
		if (chatRooms !== undefined) {
			for (const chatRoom of chatRooms) {
				const result = await chatRoom.removeMember(this.id, notes || 'User deleted', force)
				if (!result.passed) return result
			}
		}

		// If force is set to false and the user is being referenced by other documents, set the user to inactive instead of deleting them.
		if (!force && Object.keys(references).length > 0) {
			this.setActive(false, notes || 'User deleted')
			return apiResponse(101, code, false, 'User was made inactive', this.values, 'active')
		}

		// Log the user out of all devices.
		await this.logout()
		// TODO: Use Socket.io to log the user out of all devices.

		// Delete the user.
		await this.model.deleteOne()
		return apiResponse(100, code, true, 'User deleted successfully', this.values)
	}

	/// ACTIONS ///
	/** Login the user.
	 * 
	 * @param password The password of the user.
	 * @returns The response from the API.
	 */
	async login(password: string): Promise<ApiResponse> {
		const code = 'user-login'

		// Check if the password is correct.
		const passwordIsValid = await this.confirmPassword(password)
		if (!passwordIsValid) return apiResponse(200, code, false, 'Invalid password', null, 'password')
		
		// Generate a token for the user.
		const token = this.generateToken()
		if (!token) return apiResponse(201, code, false, 'Failed to generate token', null, 'token')

		// Set the status of the user to online.
		this.setStatus(Status.ONLINE)

		// Return the response.
		return apiResponse(100, code, true, 'User logged in successfully', { user: this.values, token })
	}
	
	/** Logout the user.
	 * 
	 * @returns The response from the API.
	 */
	async logout(): Promise<ApiResponse> {
		const code = 'user-logout'
		
		// TODO: Use Socket.io to check if the user is logged in on any other devices. If not, set the user status to offline.

		return apiResponse(100, code, true, 'User logged out successfully', { user: this.values })
	}

	/** Generate a token for the user. */
	private generateToken(): string {
		return jwt.sign({ id: this.id }, SECRET_KEY, { expiresIn: EXPIRATION_TIME })
	}

	//////////////////////
	/// STATIC METHODS ///
	//////////////////////

	/// CHECK METHODS ///
	/** Check if the username meets the requirements.
	 *
	 * @param username The username to check.
	 * @param ignoreId If provided, the user with this ID will be ignored when checking for existing users with the same username.
	 * @returns The response from the API.
	 */
	static async checkUsername(username: string, ignoreId?: string): Promise<ApiResponse> {
		const code = 'user-class-check-username'

		if (!username) {
			return apiResponse(200, code, false, 'No username provided', username, 'username')
		}

		if (USERNAME_REQUIERMENTS.minLength && username.length < USERNAME_REQUIERMENTS.minLength) {
			const msg = `Username must be at least ${USERNAME_REQUIERMENTS.minLength} characters long`
			return apiResponse(201, code, false, msg, username, 'username')
		}

		if (USERNAME_REQUIERMENTS.maxLength && username.length > USERNAME_REQUIERMENTS.maxLength) {
			const msg = `Username must be at most ${USERNAME_REQUIERMENTS.maxLength} characters long`
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

	/** Check if the email meets the requirements.
	 *
	 * @param email The email to check.
	 * @param ignoreId If provided, the user with this ID will be ignored when checking for existing users with the same email.
	 * @returns The response from the API.
	 */
	static async checkEmail(email: string, ignoreId?: string): Promise<ApiResponse> {
		const code = 'user-class-check-email'

		if (!email) {
			return apiResponse(200, code, false, 'No email provided', email, 'email')
		}

		if (!EMAIL_REQUIERMENTS.regex.test(email)) {
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

	/** Check if the password meets the requirements.
	 *
	 * @param password The password to check.
	 * @param getAllErrors If true, return all errors. If false, return the first error.
	 * @returns The response from the API.
	 */
	static async checkPassword(password: string, confirm?: string, getAllErrors?: boolean): Promise<ApiResponse> {
		const code = 'user-class-check-password'

		if (getAllErrors) {
			const requirements = {} as { [any: string]: [boolean, string] }

			if (PASSWORD_REQUIREMENTS.minLength && PASSWORD_REQUIREMENTS.maxLength) {
				requirements.length = [
					password.length >= PASSWORD_REQUIREMENTS.minLength && password.length <= PASSWORD_REQUIREMENTS.maxLength,
					`Password must be between ${PASSWORD_REQUIREMENTS.minLength} and ${PASSWORD_REQUIREMENTS.maxLength} characters long`
				]
			} else if (PASSWORD_REQUIREMENTS.minLength) {
				requirements.length = [
					password.length >= PASSWORD_REQUIREMENTS.minLength,
					`Password must be at least ${PASSWORD_REQUIREMENTS.minLength} characters long`
				]
			} else if (PASSWORD_REQUIREMENTS.maxLength) {
				requirements.length = [
					password.length <= PASSWORD_REQUIREMENTS.maxLength,
					`Password must be at most ${PASSWORD_REQUIREMENTS.maxLength} characters long`
				]
			}

			if (PASSWORD_REQUIREMENTS.lowercase) {
				requirements.hasLowercase = [/[a-z]/.test(password), 'Password must contain at least one lowercase letter']
			}

			if (PASSWORD_REQUIREMENTS.uppercase) {
				requirements.hasUppercase = [/[A-Z]/.test(password), 'Password must contain at least one uppercase letter']
			}

			if (PASSWORD_REQUIREMENTS.number) {
				requirements.hasNumber = [/[0-9]/.test(password), 'Password must contain at least one number']
			}

			if (PASSWORD_REQUIREMENTS.specialCharacter) {
				requirements.hasSpecialCharacter = [
					new RegExp(`[${PASSWORD_REQUIREMENTS.characters}]`).test(password),
					`Password must contain at least one special character (${PASSWORD_REQUIREMENTS.characters})`
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

		if (password.length < PASSWORD_REQUIREMENTS.minLength) {
			const msg = `Password must be at least ${PASSWORD_REQUIREMENTS.minLength} characters long`
			return apiResponse(202, code, false, msg, null, 'password')
		}

		if (password.length > PASSWORD_REQUIREMENTS.maxLength) {
			const msg = `Password must be at most ${PASSWORD_REQUIREMENTS.maxLength} characters long`
			return apiResponse(203, code, false, msg, null, 'password')
		}

		if (PASSWORD_REQUIREMENTS.lowercase && !/[a-z]/.test(password)) {
			const msg = 'Password must contain at least one lowercase letter'
			return apiResponse(204, code, false, msg, null, 'password')
		}

		if (PASSWORD_REQUIREMENTS.uppercase && !/[A-Z]/.test(password)) {
			const msg = 'Password must contain at least one uppercase letter'
			return apiResponse(205, code, false, msg, null, 'password')
		}

		if (PASSWORD_REQUIREMENTS.number && !/[0-9]/.test(password)) {
			const msg = 'Password must contain at least one number'
			return apiResponse(206, code, false, msg, null, 'password')
		}

		if (PASSWORD_REQUIREMENTS.specialCharacter && !new RegExp(`[${PASSWORD_REQUIREMENTS.characters}]`).test(password)) {
			const msg = `Password must contain at least one special character (${PASSWORD_REQUIREMENTS.characters})`
			return apiResponse(207, code, false, msg, null, 'password')
		}

		if (confirm && password !== confirm) {
			const msg = 'Passwords do not match'
			return apiResponse(208, code, false, msg, null, 'confirm-password')
		}

		return apiResponse(100, code, true, 'Password is valid')
	}

	/// CONFIRM PASSWORD ///
	/** Confirm if the provided password matches the hashed password.
	 *
	 * @param password The password to confirm.
	 * @param hash The hashed password to compare against.
	 * @returns True if the password matches, otherwise false.
	 */
	static confirmPassword(password: string, hash: string): boolean {
		return bcrypt.compareSync(password, hash)
	}

	/// SEARCH METHODS ///
	/** Search for users by id
	 * 
	 * @param id The id of the user to search for.
	 * @returns The user with the given id.
	 */
	static async findById(id: string): Promise<User | null> {
		const model = await UserModel.findById(id)
		if (!model) return null

		const user = new User(model)

		return user
	}

	/** Search for users by username
	 * 
	 * @param username The username of the user to search for.
	 * @returns The user with the given username.
	 */
	static async findByUsername(username: string): Promise<User | null> {
		const model = await UserModel.findOne({ username: { $regex: `^${username}$`, $options: 'i' } })
		if (!model) return null

		return new User(model)
	}

	/** Search for users by email
	 * 
	 * @param email The email of the user to search for.
	 * @returns The user with the given email.
	 */
	static async findByEmail(email: string): Promise<User | null> {
		const model = await UserModel.findOne({ email: { $regex: `^${email}$`, $options: 'i' } })
		if (!model) return null

		return new User(model)
	}

	/** Search for users by username or email
	 * 
	 * @param credentials The username or email of the user to search for.
	 * @returns The user with the given username or email.
	 */
	static async findByCredentials(credentials: string): Promise<User | null> {
		const model = await UserModel.findOne({
			$or: [
				{ username: { $regex: `^${credentials}$`, $options: 'i' } },
				{ email: { $regex: `^${credentials}$`, $options: 'i' } }
			]
		})
		if (!model) return null

		return new User(model)
	}

	/** Search for users by token.
	 * 
	 * @param token The token of the user to search for.
	 * @returns The user with the given token.
	 */
	static async findByToken(token: string | null): Promise<User | null> {
		const decoded = User.verifyToken(token)
		if (!decoded) return null

		// Find the user by ID
		const userId = typeof decoded === 'string' ? decoded : decoded.userId
		return await User.findById(userId)
	}

	/// ACTIONS ///
	/** Create a new user.
	 * 
	 * @param params The user information to create. Not all fields are required. Only the fields that are provided will be created.
	 * - username: The username of the user.
	 * - email: The email of the user.
	 * - password: The password of the user.
	 * - confirm: The string used to confirm the password was entered correctly.
	 * - status: The status of the user. (optional)
	 * - preferences: The preferences of the user. (optional)
	 * - active: The active status of the user. (optional)
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	static async create(params: IUserCreate, notes?: string): Promise<ApiResponse> {
		const code = 'user-class-create'

		// Check that the new values meet the requirements.
		if (params.username !== undefined) {
			const result = await User.checkUsername(params.username)
			if (!result.passed) return result
		}
		if (params.email !== undefined) {
			const result = await User.checkEmail(params.email)
			if (!result.passed) return result
		}
		if (params.password !== undefined) {
			const result = await User.checkPassword(params.password, params.confirm, true)
			if (!result.passed) return result
		}
		if (params.status !== undefined) {
			const result = Object.values(Status).includes(params.status)
			if (!result) return apiResponse(200, code, false, 'Invalid status', params.status, 'status')
		}
		if (params.preferences?.theme !== undefined) {
			const result = Object.values(Theme).includes(params.preferences.theme)
			if (!result) return apiResponse(201, code, false, 'Invalid theme', params.preferences.theme, 'theme')
		}
		if (params.active !== undefined) {
			const result = typeof params.active === 'boolean'
			if (!result) return apiResponse(202, code, false, 'Invalid active status', params.active, 'active')
		}

		// Create the user.
		const model = new UserModel({
			username: params.username,
			email: params.email,
			hash: await bcrypt.hash(params.password, 10),
			status: params.status || Status.OFFLINE,
			preferences: params.preferences || { theme: Theme.SYSTEM },
			active: params.active ?? true
		})
		if (!model) return apiResponse(203, code, false, 'Failed to create user', null, 'user')
		
		model.updateLog.push({
			timestamp: new Date(),
			notes: notes || 'User created',
			changes: {
				username: model.username,
				email: model.email,
				hash: model.hash,
				status: model.status,
				preferences: model.preferences,
				active: model.active
			}
		})
		model.save()
		const newUser = new User(model)

		return apiResponse(100, code, true, 'User created successfully', newUser.values)
	}

	/** Update the user information.
	 * 
	 * @param id The id of the user to update.
	 * @param params The user information to update. Not all fields are required. Only the fields that are provided will be updated.
	 * - username: Replace the username with the provided value.
	 * - email: Replace the email with the provided value.
	 * - password: Replace the password with the provided value.
	 * - confirm: The string used to confirm the password was entered correctly.
	 * - status: Replace the status with the provided value.
	 * - preferences: Replace all or part of the preferences with the provided values.
	 * - active: Replace the active status with the provided value.
	 * @param password The password of the user. Some fields require the password to be provided in order to be updated.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	static async update(id: string, params: IUserUpdateParams, password?: string, notes?: string): Promise<ApiResponse> {
		const code = 'user-class-update'

		// Find the user.
		const user = await User.findById(id)
		if (!user) return apiResponse(200, code, false, 'User not found', null, 'id')

		// Update the user.
		return user.update(params, password, notes)
	}

	/** Delete the user.
	 * 
	 * @param id The id of the user to delete.
	 * @param password The password of the user. This is used to confirm that the user wants to delete their account.
	 * @param force If true, the user will be deleted even if they are being referenced by other documents. If false, the user will be
	 * deleted only if they are not being referenced by other documents. Otherwise, the user will be set to inactive instead.
	 * @param notes The notes to add to the updateLog. (optional)
	 * @returns The response from the API.
	 */
	static async delete(id: string, password: string, force?: boolean, notes?: string): Promise<ApiResponse> {
		const code = 'user-class-delete'

		// Find the user.
		const user = await User.findById(id)
		if (!user) return apiResponse(200, code, false, 'User not found', null, 'id')

		// Delete the user.
		return user.delete(password, force, notes)
	}

	/** Login a user.
	 * 
	 * @param credentials The username or email of the user to login.
	 * @param password The password of the user.
	 * @returns The response from the API.
	 */
	static async login(credentials: string, password: string): Promise<ApiResponse> {
		const code = 'user-class-login'

		// Find the user.
		const user = await User.findByCredentials(credentials)
		if (!user) return apiResponse(200, code, false, 'User not found', null, 'credentials')

		// Login the user.
		return user.login(password)
	}

	/** Logout a user.
	 * 
	 * @param id The id of the user to logout.
	 * @returns The response from the API.
	 */
	static async logout(id: string): Promise<ApiResponse> {
		const code = 'user-class-logout'
		
		// Find the user.
		const user = await User.findById(id)
		if (!user) return apiResponse(200, code, false, 'User not found', null, 'id')

		// Logout the user.
		return user.logout()
	}

	/// MIDDLEWARE ///
	/** Verify the token and return the decoded token if valid, otherwise null.
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

	/** Get the token from the request. The token can be in the cookies or in the Authorization header.
	 *
	 * @param req The request object.
	 * @returns The token if found, otherwise null.
	 */
	static getToken(req: Request): string | null {
		return req.cookies?.token || req.headers?.authorization?.split(' ')[1] || null
	}

	/** Get the time left on the token in seconds.
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
		const userId = typeof decoded === 'string' ? decoded : decoded.id
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
		const userId = typeof decoded === 'string' ? decoded : decoded.id
		const user = await User.findById(userId)
		req.body.user = user
		next()
	}
}

export default User
