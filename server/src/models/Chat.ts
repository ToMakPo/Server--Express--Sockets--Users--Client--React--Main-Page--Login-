import mongoose, { Schema, Document, ObjectId, Types } from 'mongoose'
import { Response as ApiResponse, response as apiResponse } from '../lib/response'
import { Request, Response, NextFunction } from 'express'
import User, { IUserValues } from './User'
import DatabaseModel from './Modal'

/** The role of the member in the chat room.
 * 
 * @enum {string} MemberRole
 * - ***owner:*** The user who owns the chat room. Usually the creator of the chat room, however, owner can pass title to another member.
 * The owner has higher privileges than admin and member. There can only be one owner in a chat room.
 * - ***admin:*** A user who has administrative privileges in the chat room. Admins can manage members, delete messages, and perform other
 * administrative tasks. There can be multiple admins in a chat room.
 * - ***member:*** A user who is a member of the chat room. Members can send and receive messages, but they do not have administrative
 * privileges.
 */
export enum MemberRole {
	OWNER = 'owner',
	ADMIN = 'admin',
	MEMBER = 'member'
}
/** The status of the member in the chat room.
 * 
 * @enum {string} MemberStatus
 * - ***invited:*** The user has been invited to the chat room but has not yet joined.
 * - ***member:*** The user is a member of the chat room.
 * - ***rejected:*** The user has been invited to the chat room but has rejected the invitation. The user can still join the chat room if
 * they change their mind.
 * - ***archived:*** The user has archived the chat room and it will no longer show up in the main list and they will not receive
 * notifications for new messages. They can still see the chat room in the archived list and they can unarchive it at any time.
 * - ***banned:*** The user has been banned from the chat room and cannot join or see the chat room. Admins can ban and unban members.
 * Owners can ban and unban members and admins.
 */
export enum MemberStatus {
	INVITED = 'invited',
	MEMBER = 'member',
	REJECTED = 'rejected',
	ARCHIVED = 'archived',
	BANNED = 'banned'
}
/** The type of the message in the chat room.
 * 
 * @enum {string} ChatLogType
 * - ***text:*** A text message.
 * - ***image:*** A message containing an image.
 * - ***video:*** A message containing a video.
 * - ***audio:*** A message containing an audio clip.
 * - ***file:*** A message containing a file.
 * - ***sticker:*** A message containing a sticker.
 * - ***location:*** A message containing a location.
 * - ***poll:*** A message containing a poll.
 */
export enum ChatLogType {
	TEXT = 'text',
	IMAGE = 'image',
	VIDEO = 'video',
	AUDIO = 'audio',
	FILE = 'file',
	STICKER = 'sticker',
	LOCATION = 'location',
	POLL = 'poll'
}
/** The content type of the chat room message. 
 * Chat log value:
 * - ***text:*** `string` formated as markdown.
 * - ***image:*** `{ url: string, name: string }`
 * - ***video:*** `{ url: string, name: string }`
 * - ***audio:*** `{ url: string, name: string }`
 * - ***file:*** `{ url: string, name: string }`
 * - ***sticker:*** `string` formated as `::sticker_name::`
 * - ***location:*** `{ name: string, lat: number, lng: number }`
 * - ***poll:*** `{ question: string, options: {text: string, votes: number}[] }`
*/
export type ChatRoomContentType = string | { url: string, name: string } | { question: string, options: {text: string, votes: number}[] } | { name: string, lat: number, lng: number}

/** The chat room model interface. 
 * 
 * @param id The ID of the chat room.
 * @param name The name of the chat room.
 * @param members A list of members in the chat room.
 * - ***user:*** The user object of the member.
 * - ***role:*** The role of the member in the chat room. 
 * - ***joined:*** The date and time when the user joined the chat room.
 * - ***muteUntil:*** The user can mute the chat room until a certain date and time. If null, the user is not muted. If the date is 
 * 1970-01-01, the user is muted indefinitely or until the user unmutes the chat room. Muted users status will show that they are busy and 
 * they will not receive notifications for new messages.
 * - ***status:*** The status of the member in the chat room.
 * - ***roomName:*** Users can set a custom name for the chat room that will be visible only to them. If null, the chat room name will be used.
 * @param chatLog A list of messages in the chat room.
 * - ***id:*** The ID of the message.
 * - ***timestamp:*** The date and time when the message was sent.
 * - ***senderId:*** The ID of the user who sent the message.
 * - ***type:*** The type of the message.
 * - ***content:*** The content of the message. 
 * - ***reactions:*** A list of reactions to the message. Each reaction is an object with the user ID and the emoji used for the reaction.
 * - ***replyToId:*** The ID of the message that this message is replying to. If null, the message is not a reply.
 * - ***editedBy:*** The user ID of the user who edited the message. If null, the message has not been edited.
 * - ***editedAt:*** The date and time when the message was edited. If null, the message has not been edited.
 * - ***deletedBy:*** The user ID of the user who deleted the message. If null, the message has not been deleted.
 * - ***deletedAt:*** The date and time when the message was deleted. If null, the message has not been deleted.
 * @param preferences The preferences of the chat room.
 * - ***newMembersCanSeeOldChat:*** If true, members who join the chat room can see the chat history prior to their joining. By default, 
 * this is set to false.
 * - ***membersCanInvite:*** If true, members can invite other users to the chat room. By default, this is set to false.
 * - ***adminCanInvite:*** If true, admins can invite other users to the chat room. By default, this is set to true. If membersCanInvite is
 * true, this setting is assumed to be true.
 * - ***adminCanBan:*** If true, admins can ban members from the chat room. By default, this is set to true. Owners can always ban anyone.
 * - ***adminCanPromote:*** If true, admins can promote members to admin. By default, this is set to true. Owners can always promote
 * - ***membersCanEditMessages:*** If true, members can edit or delete their own messages. By default, this is set to true.
 * - ***adminCanEditMessages:*** If true, admins can edit or delete messages of any member. By default, this is set to true. Note: If a 
 * message is edited or deleted by an admin, it will be marked as "edited by admin" or "deleted by admin" respectively.
 * - ***slowMode:*** The time in seconds that must pass before a user can send another message. If set to 0, slow mode is disabled. By
 * default, this is set to 0. This does not apply to admins.
 * @param active The active status of the chat room. Inactive chat rooms are not visible to users.
 * @param updateLog A list of updates made to the chat room.
*/
export interface IChatRoom {
	id: string
	name: string
	members: {
		user: User
		role: MemberRole
		joined: Date
		muteUntil: Date | null
		status: MemberStatus
		roomName: string | null
	}[]
	chatLog: {
		id: string
		timestamp: Date
		senderId: string
		type: ChatLogType
		content: ChatRoomContentType
		reactions: {
			userId: string
			emoji: string
		}[]
		replyToId: string | null
		editedBy: string | null
		editedAt: Date | null
		deletedBy: string | null
		deletedAt: Date | null
	}[]
	preferences: {
		newMembersCanSeeOldChat: boolean
		membersCanInvite: boolean
		adminCanInvite: boolean
		adminCanBan: boolean
		adminCanPromote: boolean
		membersCanEditMessages: boolean
		adminCanEditMessages: boolean
		slowMode: number 
	}
	active: boolean
	updateLog: {
		timestamp: Date
		notes: string
		changes: IChatRoomUpdate
	}[]
}

/** The chat room model interface that can be sent to the client. */
export interface IChatRoomValues extends Omit<IChatRoom, 'updateLog'> {}
/** The chat room model interface that stores the changes made to the user. */
export interface IChatRoomUpdate extends Partial<Omit<IChatRoom, 'id' | 'members' | 'preferences' | 'chatLog' | 'updateLog'>> {
	updateBy: string
	members?: ({ userId: string } & Partial<Omit<IChatRoom['members'][0], 'user'>>)[]
	preferences?: Partial<IChatRoom['preferences']>
}
/** The chat room model interface that can be used to update the user. */
export interface IChatRoomUpdateParams extends IChatRoomUpdate {}

/** The chat room schema. */
const chatRoomSchema: Schema = new Schema({
	id: { type: Types.ObjectId, auto: true },
	name: { type: String, required: true, unique: false },
	members: [
		{
			userId: { type: Types.ObjectId, required: true, unique: false },
			role: { type: String, enum: MemberRole, required: true }, 
			joined: { type: Date, default: Date.now },
			muteUntil: { type: Date, default: null },
			status: { type: String, enum: MemberStatus, required: true },
			roomName: { type: String, default: null }
		}
	],
	chatLog: [
		{
			id: { type: Types.ObjectId, auto: true },
			timestamp: { type: Date, default: Date.now },
			senderId: { type: Types.ObjectId, required: true, unique: false },
			type: { type: String, enum: ChatLogType, required: true },
			content: { type: Schema.Types.Mixed, required: true },
			reactions: [{
				userId: { type: Types.ObjectId, required: true, unique: false },
				emoji: { type: String, required: true }
			}],
			replyToId: { type: Types.ObjectId, default: null },
			editedBy: { type: Types.ObjectId, default: null },
			editedAt: { type: Date, default: null },
			deletedBy: { type: Types.ObjectId, default: null },
			deletedAt: { type: Date, default: null }
		}
	],
	preferences: {
		newMembersCanSeeOldChat: { type: Boolean, default: false },
		membersCanInvite: { type: Boolean, default: false },
		adminCanInvite: { type: Boolean, default: true },
		adminCanBan: { type: Boolean, default: true },
		adminCanPromote: { type: Boolean, default: true },
		membersCanEditMessages: { type: Boolean, default: true },
		adminCanEditMessages: { type: Boolean, default: true },
		slowMode: { type: Number, default: 0 }
	},
	active: { type: Boolean, default: true },
	updateLog: [{
			timestamp: { type: Date, default: Date.now },
			notes: { type: String, default: '' },
			changes: { 
				type: {
					name: { type: String },
					members: [{
						userId: { type: Types.ObjectId, required: true, unique: false },
						role: { type: String, enum: MemberRole },
						joined: { type: Date },
						muteUntil: { type: Date },
						archived: { type: Boolean },
						status: { type: String, enum: MemberStatus },
						roomName: { type: String }
					}],
					preferences: {
						newMembersCanSeeOldChat: { type: Boolean },
						membersCanInvite: { type: Boolean },
						adminCanInvite: { type: Boolean },
						adminCanBan: { type: Boolean },
						membersCanEditMessages: { type: Boolean },
						adminCanEditMessages: { type: Boolean },
						slowMode: { type: Number }
					},
					active: { type: Boolean }
				},
				required: true
			}
		}
	]
}, { id: true, _id: false }) as unknown as Schema<IChatRoom>

const ChatRoomModel = mongoose.model<IChatRoom>('ChatRoom', chatRoomSchema)

/** The chat room object */
class ChatRoom extends DatabaseModel {
	private model: Document<unknown, {}, IChatRoom> & IChatRoom

	private constructor(chatRoom: IChatRoom) {
		super()
		this.model = new ChatRoomModel(chatRoom)
	}

	/** A list of all members in the chat room.*/
	get members(): IChatRoom['members'] {
		return JSON.parse(JSON.stringify(this.model.members)) as IChatRoom['members']
	}

	/** Get a specific member of the chat room by their user ID.
	 * 
	 * @param userId The ID of the user.
	 * @return A promise that resolves to the member object or null if the member is not found.
	 */
	async getMember(user: User | string): Promise<IChatRoom['members'][number] | null> {
		if (typeof user === 'string') {
			const found = await User.findById(user)
			if (!found) return null
			user = found
		}

		const member = this.members.find((member) => member.user.id === user.id)
		return member || null
	}

	/** Set the user as the owner of the chat room.
	 * 
	 * @param activeUser The user who is requesting to make the change.
	 * @param userId The ID of the user to set as the owner.
	 * @return A promise that resolves to an ApiResponse object.
	 * @note Only one user can be the owner of the chat room. The current owner will be set as admin.
	 */
	async setOwner(activeUser: User | string, userId: string): Promise<ApiResponse> { 
		const code = 'chat-room-set-owner'
		
		// Get the active member.
		const activeMember = await this.getMember(activeUser)
		if (!activeMember) 
			return apiResponse(200, code, false, 'Active user not found.', activeUser, 'userId')

		// Check that the active user is the owner of the chat room.
		if (activeMember.role !== MemberRole.OWNER)
			return apiResponse(201, code, false, 'Only the owner can transfer ownership.', activeMember.user.id, 'activeUserId')
		
		// Find the member with the given user ID
		const member = this.members.find((member) => member.user.id === userId)
		if (!member) return apiResponse(202, code, false, 'Member not found.', userId, 'memberId')
		
		// Check if the member is already the owner
		if (member.role === MemberRole.OWNER) 
			return apiResponse(203, code, false, 'User is already the owner.', userId, 'memberId')

		// Setup the changes object to be used in the update log
		const changes = { updateBy: activeMember.user.id } as IChatRoomUpdate
		changes.members = [] as IChatRoomUpdate['members']

		// Find the current owner and change their role to admin
		for (const other of this.members) {
			if (other.role === MemberRole.OWNER) {
				other.role = MemberRole.ADMIN
				changes.members!.push({
					userId: other.user.id,
					role: MemberRole.ADMIN
				})
				break
			}
		}
		
		// Update the member's role to owner
		member.role = MemberRole.OWNER
		changes.members!.push({
			userId: member.user.id, 
			role: MemberRole.OWNER
		})
		
		// Add the changes to the update log
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: `Ownership transferred to ${member.user.username} (${member.user.id})`,
			changes: changes
		})

		// Save the changes to the database
		await this.model.save()

		// TODO: Use Socket.IO to notify new owner that they are now the owner of the chat room.
		// TODO: Add note in chat log that ownership was transferred to the user.

		// Return a success response
		return apiResponse(100, code, true, 'Ownership transferred successfully.', userId, 'memberId')
	}

	/** Set the user as an admin of the chat room.
	 * 
	 * @param activeUser The user who is requesting to make the change.
	 * @param userId The ID of the user to set as an admin.
	 * @return A promise that resolves to an ApiResponse object.
	 */
	async setAdmin(activeUser: User | string, userId: string): Promise<ApiResponse> {
		const code = 'chat-room-set-admin'

		// Get the active member.
		const activeMember = await this.getMember(activeUser)
		if (!activeMember) 
			return apiResponse(200, code, false, 'Active user not found.', activeUser, 'userId')

		// Check that the active user has permission to promote members to admin.
		const adminCanPromote = this.model.preferences.adminCanPromote
		const hasPermission = activeMember.role === MemberRole.OWNER || (activeMember.role === MemberRole.ADMIN && adminCanPromote)

		if (!hasPermission) {
			const msg = `Only ${adminCanPromote ? 'owners and admins' : 'owners'} can promote members to admin.`
			return apiResponse(201, code, false, msg, activeMember.user.id, 'activeUserId')
		}

		// Find the member with the given user ID
		const member = this.members.find((member) => member.user.id === userId)
		if (!member) return apiResponse(202, code, false, 'Member not found.', userId, 'memberId')

		// Check if the member is already an admin
		if (member.role === MemberRole.ADMIN) 
			return apiResponse(203, code, false, 'User is already an admin.', userId, 'memberId')

		// If they are the owner, then return an error response
		if (member.role === MemberRole.OWNER)
			return apiResponse(204, code, false, 'User is the owner. Instead, set the new owner and this user will be set as admin.', 
				userId, 'memberId')

		// Setup the changes object to be used in the update log
		const changes = { updateBy: activeMember.user.id } as IChatRoomUpdate
		changes.members = [] as IChatRoomUpdate['members']

		// Update the member's role to admin
		member.role = MemberRole.ADMIN
		changes.members!.push({
			userId: member.user.id,
			role: MemberRole.ADMIN
		})
		
		// Add the changes to the update log
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: `Admin privileges granted to ${member.user.username} (${member.user.id})`,
			changes: changes
		})

		// Save the changes to the database
		await this.model.save()

		// TODO: Use Socket.IO to notify new admin that they are now an admin of the chat room.
		// Add note in chat log that admin privileges were granted to the user.

		return apiResponse(100, code, true, 'Admin privileges granted successfully.', userId, 'memberId')
	}

	/** Set the user as a member of the chat room.
	 * 
	 * @param activeUser The user who is requesting to make the change.
	 * @param userId The ID of the user to set as a member.
	 * @return A promise that resolves to an ApiResponse object.
	 */
	async setMember(activeUser: User | string, userId: string): Promise<ApiResponse> {
		const code = 'chat-room-set-member'

		// Get the active member.
		const activeMember = await this.getMember(activeUser)
		if (!activeMember) 
			return apiResponse(200, code, false, 'Active user not found.', activeUser, 'userId')

		// Check that the active user has permission to promote members to admin.
		const adminCanPromote = this.model.preferences.adminCanPromote
		const hasPermission = activeMember.role === MemberRole.OWNER || (activeMember.role === MemberRole.ADMIN && adminCanPromote)

		if (!hasPermission) {
			const msg = `Only ${adminCanPromote ? 'owners and admins' : 'owners'} can update roles.`
			return apiResponse(201, code, false, msg, activeMember.user.id, 'activeUserId')
		}

		// Find the member with the given user ID
		const member = this.members.find((member) => member.user.id === userId)
		if (!member) return apiResponse(201, code, false, 'Member not found.', userId, 'memberId')

		// Check if the member is already a member
		if (member.role === MemberRole.MEMBER)
			return apiResponse(202, code, false, 'User is already a member.', userId, 'memberId')

		// If they are the owner, then return an error response
		if (member.role === MemberRole.OWNER)
			return apiResponse(203, code, false, 'User is the owner. Instead, set the new owner and this user will be set as admin.', 
				userId, 'memberId')

		// Setup the changes object to be used in the update log
		const changes = { updateBy: activeMember.user.id } as IChatRoomUpdate
		changes.members = [] as IChatRoomUpdate['members']

		// Update the member's role to admin
		member.role = MemberRole.MEMBER
		changes.members!.push({
			userId: member.user.id,
			role: MemberRole.MEMBER
		})
		
		// Add the changes to the update log
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: `${member.user.username} (${member.user.id}) role set to ${MemberRole.MEMBER}`,
			changes: changes
		})

		// Save the changes to the database
		await this.model.save()

		// TODO: Use Socket.IO to notify user that their role was set to member.

		return apiResponse(100, code, true, 'Admin privileges granted successfully.', userId, 'memberId')
	}

	/** Remove the user from the chat room.
	 * 
	 * @param activeUser The user who is requesting to make the change.
	 * @param userId The ID of the user to remove from the chat room.
	 * @param force If true, the user will be removed from the chat room even if they are the owner. If false, the user's status will be
	 * updated instead of removing them. (optional, default: false)
	 * @param notes The notes to add to the update log. (optional)
	 * @return A promise that resolves to an ApiResponse object.
	 */
	async removeMember(activeUser: User | string, userId: string, force?: boolean, notes?: string): Promise<ApiResponse> {
		const code = 'chat-room-remove-member'

		// Get the active member.
		const activeMember = await this.getMember(activeUser)
		if (!activeMember) 
			return apiResponse(200, code, false, 'Active user not found.', activeUser, 'userId')

		// Get the member who is being removed.
		const member = await this.getMember(userId)
		if (!member) return apiResponse(201, code, false, 'Member not found.', userId, 'memberId')
		
		// Check if the active member is also the member being removed.
		const isActiveMember = activeMember.user.id === member.user.id

		// Check that the active user has permission to remove members.
		const adminCanBan = this.model.preferences.adminCanBan
		const adminCanPromote = this.model.preferences.adminCanPromote
		const hasPermission = isActiveMember ||
			activeMember.role === MemberRole.OWNER || 
			activeMember.role === MemberRole.ADMIN && member.role === MemberRole.MEMBER && adminCanBan || 
			activeMember.role === MemberRole.ADMIN && member.role === MemberRole.ADMIN && adminCanBan && adminCanPromote

		if (!hasPermission) {
			const msg = `Only ${this.model.preferences.adminCanBan ? 'owners and admins' : 'owners'} can remove other members.`
			return apiResponse(202, code, false, msg, activeMember.user.id, 'activeUserId')
		}

		// Figure out what happens when the owner is removed.
		if (member.role === MemberRole.OWNER) {
			if (!force) 
				return apiResponse(203, code, false, 'Cannot remove owner. Please transfer ownership to another member first.', userId, 'memberId')
			
			let newOwner = null

			// Find the first admin and make them the new owner
			for (const other of this.members) {
				if (other.user.id === userId) continue
				if (other.role !== MemberRole.ADMIN) continue
				newOwner = other
				break
			}

			// If no admin is found, find the first member and make them the new owner
			if (!newOwner) {
				for (const other of this.members) {
					if (other.user.id === userId) continue
					newOwner = other
					break
				}
			}

			// If no member is found, delete the chat room
			if (!newOwner) {
				return await this.delete(activeMember.user, '')
			}

			// Update the owner
			const response = await this.setOwner(activeUser, newOwner.user.id)
			if (!response.passed) return response
		}

		// If force is false, then check update the member's status instead of removing them.
		if (!force) {
			const update = (status: MemberStatus, updateNotes: string) => {
				member.status = status
				this.model.updateLog.push({
					timestamp: new Date(),
					notes: notes || updateNotes,
					changes: {
						updateBy: activeMember.user.id,
						members: [{
							userId: member.user.id,
							status: status
						}]
					}
				})
				this.model.save()

				// TODO: Use Socket.IO to notify user that they were removed from the chat room. If the user is in the chat room, then they will be
				// automatically removed from the chat room.
			}

			if (isActiveMember && member.status === MemberStatus.INVITED) {
				update(MemberStatus.REJECTED, 'Invitation rejected')
				return apiResponse(101, code, true, 'Invitation rejected successfully.', userId, 'memberId')
			}
			if (isActiveMember && member.status === MemberStatus.MEMBER) {
				update(MemberStatus.ARCHIVED, 'Chat room archived')
				return apiResponse(102, code, true, 'Chat room archived successfully.', userId, 'memberId')
			}
			if (isActiveMember && member.status === MemberStatus.ARCHIVED) {
				return apiResponse(204, code, false, 'This chat room is already archived.', userId, 'memberId')
			}
			if (isActiveMember && member.status === MemberStatus.BANNED) {
				return apiResponse(205, code, false, 'You are already banned from this chat room.', userId, 'memberId')
			}
			if (isActiveMember && member.status === MemberStatus.REJECTED) {
				return apiResponse(206, code, false, 'You have already rejected the invitation to this chat room.', userId, 'memberId')
			}

			if (!isActiveMember && member.status === MemberStatus.INVITED) {
				update(MemberStatus.BANNED, 'Member banned')
				return apiResponse(103, code, true, 'Member banned successfully.', userId, 'memberId')
			}
			if (!isActiveMember && member.status === MemberStatus.MEMBER) {
				update(MemberStatus.BANNED, 'Member banned')
				return apiResponse(104, code, true, 'Member banned successfully.', userId, 'memberId')
			}
			if (!isActiveMember && member.status === MemberStatus.ARCHIVED) {
				update(MemberStatus.BANNED, 'Member banned')
				return apiResponse(105, code, true, 'Member banned successfully.', userId, 'memberId')
			}
			if (!isActiveMember && member.status === MemberStatus.BANNED) {
				return apiResponse(206, code, false, 'User is already banned from this chat room.', userId, 'memberId')
			}
			if (!isActiveMember && member.status === MemberStatus.REJECTED) {
				update(MemberStatus.BANNED, 'Member banned')
				return apiResponse(107, code, true, 'Member banned successfully.', userId, 'memberId')
			}
		}

		// Remove the member from the chat room
		this.model.members = this.model.members.filter((member) => member.user.id !== userId)
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: notes || `${member.user.username} (${member.user.id}) removed from chat room`,
			changes: { 
				updateBy: activeMember.user.id, 
				members: [{ userId: member.user.id }] 
			}
		})
		await this.model.save()

		// TODO: Use Socket.IO to notify user that they were removed from the chat room. If the user is in the chat room, then they will be
		// automatically removed from the chat room.

		return apiResponse(100, code, true, 'Member removed successfully.', userId, 'memberId')
	}

	/** Delete the chat room.
	 * 
	 * @param activeUser The user who is requesting to make the change.
	 * @param notes The notes to add to the update log. (optional)
	 * @return A promise that resolves to an ApiResponse object.
	 */
	async delete(activeUser: User | string, notes?: string): Promise<ApiResponse> {
		const code = 'chat-room-delete'

		// Get the active member.
		const activeMember = await this.getMember(activeUser)
		if (!activeMember) 
			return apiResponse(200, code, false, 'Active user not found.', activeUser, 'userId')

		// Check that the active user is the owner of the chat room.
		if (activeMember.role !== MemberRole.OWNER)
			return apiResponse(201, code, false, 'Only the owner can delete the chat room.', activeMember.user.id, 'activeUserId')

		// Delete the chat room
		this.model.updateLog.push({
			timestamp: new Date(),
			notes: notes || `Chat room deleted by ${activeMember.user.username} (${activeMember.user.id})`,
			changes: { updateBy: activeMember.user.id }
		})
		await this.model.save()
		ChatRoomModel.deleteOne({ id: this.model.id }).exec()

		return apiResponse(100, code, true, 'Chat room deleted successfully.')
	}

	//////////////////////
	/// STATIC METHODS ///
	//////////////////////
	
	/** Find all chat rooms that a user is a member of.
	 * 
	 * @param userId The ID of the user.
	 * @return A promise that resolves to an array of chat rooms that the user is a member of.
	 */
	static async findAllByUserId(userId: string): Promise<ChatRoom[]> {
		const records = await ChatRoomModel.find({ 'members.userId': userId }).exec()
		const chatRooms = records.map((chatRoom) => new ChatRoom(chatRoom))
		return chatRooms
	}
}

export default ChatRoom
