//! Wire protocol shared by the Zeevum server and its clients.
//!
//! Transport is line-delimited JSON over TLS, one frame per message, terminated
//! by `\n`. See [`encode`] and [`decode`].
//!
//! Two distinct identifiers, and mixing them up is the mistake this module
//! exists to prevent.
//!
//! - [`UserId`], who somebody is. Public, stable, safe to show and to look
//!   up by login.
//! - [`ConvId`], where a message goes. A conversation, a 1:1 chat today, a
//!   group in the future. Opaque to clients, obtain one from the server,
//!   [`ServerMsg::DmResolved`], [`ServerMsg::FriendList`], group creation, and
//!   store it. Never derive or guess one.
//!
//! Addressing messages by `ConvId` rather than by peer is what keeps group
//! chats and end-to-end encryption additive instead of breaking, both need
//! "the conversation" to be a first-class object that is not the same thing as
//! "the other participant".

use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt;
use uuid::Uuid;

pub mod pow;

/// Bumped on every breaking change to the message types. Renaming a field,
/// changing a type, removing a variant. Adding a variant breaks older receivers
/// too, so it counts as breaking as well.
pub const PROTOCOL_VERSION: u32 = 5;
pub const MAX_LOGIN_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 4096;
/// The longest a group title may be, checked on creation and on rename.
pub const MAX_TITLE_LEN: usize = 64;
/// A frame longer than this closes the connection.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const HISTORY_LIMIT: i64 = 50;

pub type UserId = i64;

/// Opaque to clients.
pub type ConvId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserBrief {
    pub user_id: UserId,
    pub login: String,
}

/// What an administrator of a group may do. The owner's set is always full,
/// so an owner is never described by this type.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminRights {
    pub change_info: bool,
    pub invite_users: bool,
    pub ban_users: bool,
    pub add_admins: bool,
}

/// A member's standing in a group. The owner is who the group belongs to;
/// their rights are always the full set.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Owner,
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMember {
    pub user: UserBrief,
    pub role: MemberRole,
    /// Meaningful for an admin; sent full for the owner, so a reader never
    /// has to special-case the field.
    pub rights: AdminRights,
}

/// The one line a conversation list entry shows under its title.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LastMessage {
    pub message_id: Uuid,
    pub sender_user_id: UserId,
    pub timestamp: i64,
    /// Truncated by the server, so the list never drags whole messages.
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChatKind {
    Private {
        peer: UserBrief,
    },
    /// `you_left` is the owner who left but kept the ownership: the
    /// conversation stays in their list so they can come back or delete the
    /// group. False for everybody else.
    Group {
        title: String,
        you_left: bool,
    },
}

/// One row of the conversation list, the starting state after
/// [`ServerMsg::AuthOk`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatEntry {
    pub conv_id: ConvId,
    pub kind: ChatKind,
    /// Messages by others past the reader's read cursor.
    pub unread: u32,
    pub last: Option<LastMessage>,
}

/// Clients branch on the variant, never on text. Text in
/// [`ServerMsg::Error::detail`] is for logs and debugging only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ErrorCode {
    //
    // Handshake
    //
    /// The client speaks a protocol version this server does not support.
    UnsupportedProtocolVersion {
        server_version: u32,
    },
    /// Wrong login or password, or an invalid/expired token.
    InvalidCredentials,
    /// Login taken, malformed, or password too weak.
    RegistrationFailed,
    /// The password was reset by an admin and has to be replaced before
    /// anything else is allowed.
    MustChangePassword,
    /// The frame could not be parsed, or arrived when it was not allowed.
    MalformedFrame,

    //
    // Authorization
    //
    /// The user is not a participant of the conversation they addressed.
    NotAMember,
    /// Distinct from [`ErrorCode::NotAMember`], that one is about a conversation
    /// that exists, this one is about a relationship that does not. A client that
    /// receives this on `ResolveDm` should offer to add the peer.
    ///
    /// Deliberately does not separate "never were friends" from "blocked", the
    /// caller must not be able to tell the difference.
    NotFriends,
    NoPendingRequest,
    AlreadyFriends,
    CannotTargetYourself,
    ConversationNotFound,
    UserNotFound,

    //
    // Groups
    //
    /// The right the action needs is missing, or is reserved for the owner.
    NotPermitted,
    AlreadyMember,
    /// The group title exceeds [`MAX_TITLE_LEN`].
    TitleTooLong,

    //
    // Messages
    //
    /// Content exceeds [`MAX_MESSAGE_LEN`].
    MessageTooLong,

    //
    // Server
    //
    Internal,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProtocolVersion { server_version } => write!(
                f,
                "Protocol version is not supported. Server speaks v{server_version}. Update your client."
            ),
            Self::InvalidCredentials => write!(f, "Wrong login or password"),
            Self::RegistrationFailed => write!(
                f,
                "Registration failed. Check login format and password strength."
            ),
            Self::MustChangePassword => write!(
                f,
                "Your password was reset by an administrator and has to be changed before you can continue."
            ),
            Self::MalformedFrame => write!(f, "Malformed frame"),
            Self::NotAMember => write!(f, "You are not a member of this conversation"),
            Self::NotFriends => write!(f, "You are not friends with this user"),
            Self::NoPendingRequest => write!(f, "No pending friend request from this user"),
            Self::AlreadyFriends => write!(f, "Already friends"),
            Self::CannotTargetYourself => write!(f, "Cannot target yourself"),
            Self::ConversationNotFound => write!(f, "Conversation not found"),
            Self::UserNotFound => write!(f, "User not found"),
            Self::NotPermitted => write!(f, "Not enough rights"),
            Self::AlreadyMember => write!(f, "Already a member"),
            Self::TitleTooLong => write!(f, "Group title is too long"),
            Self::MessageTooLong => write!(f, "Message too long"),
            Self::Internal => write!(f, "Internal server error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Must be the first frame on every connection
    Auth {
        protocol_version: u32,
        method: AuthMethod,
    },
    PowSolution {
        nonce: u64,
    },
    SearchUser {
        login: String,
    },
    FriendReq {
        target_user_id: UserId,
    },
    AcceptFriend {
        target_user_id: UserId,
    },
    /// Created on first use
    ResolveDm {
        peer_user_id: UserId,
    },
    HistoryReq {
        conv_id: ConvId,
    },
    /// `message_id` is generated by the client so that it can match the
    /// acknowledgement to the message it optimistically rendered
    SendMsg {
        message_id: Uuid,
        conv_id: ConvId,
        content: String,
    },
    /// Notifies the sender
    MarkRead {
        message_id: Uuid,
    },
    /// The creator becomes the owner, everyone listed joins as a member.
    /// Every one of them must be a friend of the creator's; an empty list is
    /// fine, members can be added later.
    CreateGroup {
        title: String,
        members: Vec<UserId>,
    },
    /// Requires the `invite_users` right; the invitee must be a friend of
    /// the inviter's and not a member yet.
    GroupAddMember {
        conv_id: ConvId,
        target_user_id: UserId,
    },
    /// Requires the `ban_users` right. An administrator can only be removed
    /// by the owner; the owner by nobody.
    GroupRemoveMember {
        conv_id: ConvId,
        target_user_id: UserId,
    },
    /// Requires the `add_admins` right, and the rights granted may not
    /// exceed the granter's. Zero rights demotes back to a member.
    GroupSetAdmin {
        conv_id: ConvId,
        target_user_id: UserId,
        rights: AdminRights,
    },
    /// Requires the `change_info` right.
    RenameGroup {
        conv_id: ConvId,
        title: String,
    },
    /// The owner's flag decides what happens to the ownership: handed to the
    /// first administrator, or kept, so the owner can [`ClientMsg::JoinGroup`]
    /// later. Ignored for everyone else, who just leaves.
    LeaveGroup {
        conv_id: ConvId,
        #[serde(default)]
        transfer_ownership: bool,
    },
    /// The owner coming back to a group they left without transferring.
    JoinGroup {
        conv_id: ConvId,
    },
    /// Owner only, whether they are a participant or left with the ownership
    /// kept.
    DeleteGroup {
        conv_id: ConvId,
    },
    /// `all_sessions` also drops every other session of the user. The server
    /// closes the connection either way
    Logout {
        all_sessions: bool,
    },
    /// Replaces the password and clears the flag that locked the account.
    /// The old one is asked for even though the session is already proven,
    /// so that a token alone is not enough to take an account over.
    ///
    /// The only frame accepted while `must_change_password` is set.
    ChangePassword {
        old_password: String,
        new_password: String,
    },
}

/// Registration additionally requires proof of work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    Token {
        token: String,
    },
    Login {
        login: String,
        password: String,
    },
    Register {
        login: String,
        password: String,
        /// Required when the server only registers by invitation. Optional
        /// on the wire: a frame without it is one from before invitations
        /// existed, and parses the same.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invite_code: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Sent before registration is processed.
    PowChallenge {
        challenge: String,
        difficulty_bits: u32,
    },
    /// `must_change_password` locks everything except
    /// [`ClientMsg::ChangePassword`]. Sent again, cleared, once the password
    /// has been replaced, so that a client needs only one path out of the
    /// lock.
    AuthOk {
        user_id: UserId,
        token: String,
        expires_at: i64,
        must_change_password: bool,
    },
    /// Also used for handshake failures.
    Error {
        code: ErrorCode,
        /// Free-form detail for logs and debugging. Never shown to users as-is.
        detail: Option<String>,
    },
    /// Starting state, accepted friends.
    FriendList {
        entries: Vec<UserBrief>,
    },
    /// Starting state, incoming friend requests.
    PendingReqs {
        entries: Vec<UserBrief>,
    },
    /// Starting state: every conversation of the user's, private and group
    /// alike, with what the list shows — the unread count and the last
    /// message.
    ChatList {
        entries: Vec<ChatEntry>,
    },
    /// While you are online, a push rather than part of the starting state.
    IncomingReq {
        from: UserBrief,
    },
    /// Sent to both sides.
    FriendAdded {
        user: UserBrief,
    },
    FriendReqSent {
        user: UserBrief,
    },
    UserFound {
        user: UserBrief,
    },
    UserNotFound,
    DmResolved {
        conv_id: ConvId,
        peer: UserBrief,
    },
    /// The whole truth about a group: title, membership, roles, rights. Sent
    /// to every participant on creation and on every change; whoever was
    /// removed gets [`ServerMsg::RemovedFromGroup`] instead.
    GroupInfo {
        conv_id: ConvId,
        title: String,
        members: Vec<GroupMember>,
    },
    /// The conversation is gone for the recipient: removed from the group,
    /// left it, or the group was deleted.
    RemovedFromGroup {
        conv_id: ConvId,
    },
    /// The batch ends with [`ServerMsg::HistoryEnd`].
    HistoryMsg {
        message_id: Uuid,
        conv_id: ConvId,
        sender_user_id: UserId,
        timestamp: i64,
        content: String,
        is_read: bool,
    },
    HistoryEnd {
        conv_id: ConvId,
    },
    MsgAck {
        message_id: Uuid,
        conv_id: ConvId,
    },
    RecvMsg {
        message_id: Uuid,
        conv_id: ConvId,
        sender_user_id: UserId,
        timestamp: i64,
        content: String,
    },
    MsgRead {
        message_id: Uuid,
        conv_id: ConvId,
    },
}

pub fn encode<T: Serialize>(msg: &T) -> serde_json::Result<String> {
    let mut line = serde_json::to_string(msg)?;
    line.push('\n');
    Ok(line)
}

pub fn decode<T: serde::de::DeserializeOwned>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim())
}

/// Reads one `\n`-terminated frame, terminator included. Whatever arrived
/// before the peer closed the stream is returned as the last frame, cut
/// short; the caller decides what that is worth.
///
/// A frame longer than [`MAX_LINE_BYTES`] is
/// [`std::io::ErrorKind::InvalidData`], which both ends read as "close the
/// connection": a stranger must not be able to hold it open with an
/// endless line.
pub async fn read_frame<S>(reader: &mut S) -> std::io::Result<String>
where
    S: AsyncBufReadExt + Unpin,
{
    let mut out: Vec<u8> = Vec::with_capacity(512);

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            out.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            return if out.len() > MAX_LINE_BYTES {
                Err(frame_too_long())
            } else {
                Ok(String::from_utf8_lossy(&out).into_owned())
            };
        }

        out.extend_from_slice(available);
        let used = available.len();
        reader.consume(used);

        if out.len() > MAX_LINE_BYTES {
            return Err(frame_too_long());
        }
    }
}

fn frame_too_long() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "frame exceeds MAX_LINE_BYTES",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::BufReader;

    fn reader(bytes: &[u8]) -> BufReader<std::io::Cursor<&[u8]>> {
        BufReader::new(std::io::Cursor::new(bytes))
    }

    #[tokio::test]
    async fn frames_come_out_one_per_call_with_terminators() {
        let mut r = reader(b"{\"x\":1}\n{\"x\":2}\n");
        assert_eq!(read_frame(&mut r).await.unwrap(), "{\"x\":1}\n");
        assert_eq!(read_frame(&mut r).await.unwrap(), "{\"x\":2}\n");
        assert_eq!(read_frame(&mut r).await.unwrap(), "");
    }

    /// The peer is free to drop mid-line; what arrived is the frame, the
    /// caller decides what a frame without its terminator is worth.
    #[tokio::test]
    async fn a_frame_cut_short_by_eof_comes_back_as_is() {
        let mut r = reader(b"{\"x\":1}\n{\"x\":2}");
        assert_eq!(read_frame(&mut r).await.unwrap(), "{\"x\":1}\n");
        assert_eq!(read_frame(&mut r).await.unwrap(), "{\"x\":2}");
    }

    #[tokio::test]
    async fn a_frame_past_the_limit_is_invalid_data() {
        let mut oversized = vec![b'a'; MAX_LINE_BYTES];
        oversized.push(b'\n');
        let mut r = reader(&oversized);
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_frame_exactly_at_the_limit_is_still_a_frame() {
        let mut at_limit = vec![b'a'; MAX_LINE_BYTES - 1];
        at_limit.push(b'\n');
        let mut r = reader(&at_limit);
        let frame = read_frame(&mut r).await.unwrap();
        assert_eq!(frame.len(), MAX_LINE_BYTES);
    }

    /// No newline at all, just an endless stream: the limit has to close
    /// this, not the terminator.
    #[tokio::test]
    async fn an_endless_line_without_a_terminator_is_cut_by_the_limit() {
        let endless = vec![b'a'; MAX_LINE_BYTES + 1];
        let mut r = reader(&endless);
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn roundtrip_chat_list() {
        let msg = ServerMsg::ChatList {
            entries: vec![
                ChatEntry {
                    conv_id: Uuid::new_v4(),
                    kind: ChatKind::Private {
                        peer: UserBrief {
                            user_id: 7,
                            login: "alice".into(),
                        },
                    },
                    unread: 3,
                    last: Some(LastMessage {
                        message_id: Uuid::new_v4(),
                        sender_user_id: 7,
                        timestamp: 1730000000,
                        preview: "привет".into(),
                    }),
                },
                ChatEntry {
                    conv_id: Uuid::new_v4(),
                    kind: ChatKind::Group {
                        title: "Дача".into(),
                        you_left: false,
                    },
                    unread: 0,
                    last: None,
                },
                ChatEntry {
                    conv_id: Uuid::new_v4(),
                    kind: ChatKind::Group {
                        title: "Покинутая".into(),
                        you_left: true,
                    },
                    unread: 0,
                    last: None,
                },
            ],
        };
        let line = encode(&msg).unwrap();
        let back: ServerMsg = decode(&line).unwrap();
        assert_eq!(back, msg);
    }

    /// The common case at login: no conversations at all.
    #[test]
    fn an_empty_chat_list_is_still_a_frame() {
        let msg = ServerMsg::ChatList { entries: vec![] };
        let line = encode(&msg).unwrap();
        let back: ServerMsg = decode(&line).unwrap();
        assert_eq!(back, msg);
    }

    /// One of each role, so a missing role or a broken rights shape fails
    /// here rather than in a client.
    #[test]
    fn roundtrip_group_info() {
        let msg = ServerMsg::GroupInfo {
            conv_id: Uuid::new_v4(),
            title: "Дача".into(),
            members: vec![
                GroupMember {
                    user: UserBrief {
                        user_id: 1,
                        login: "owner".into(),
                    },
                    role: MemberRole::Owner,
                    rights: AdminRights {
                        change_info: true,
                        invite_users: true,
                        ban_users: true,
                        add_admins: true,
                    },
                },
                GroupMember {
                    user: UserBrief {
                        user_id: 2,
                        login: "admin".into(),
                    },
                    role: MemberRole::Admin,
                    rights: AdminRights {
                        invite_users: true,
                        ..AdminRights::default()
                    },
                },
                GroupMember {
                    user: UserBrief {
                        user_id: 3,
                        login: "member".into(),
                    },
                    role: MemberRole::Member,
                    rights: AdminRights::default(),
                },
            ],
        };
        let line = encode(&msg).unwrap();
        let back: ServerMsg = decode(&line).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn roundtrip_create_group() {
        let msg = ClientMsg::CreateGroup {
            title: "Дача".into(),
            members: vec![7, 9, 11],
        };
        let back: ClientMsg = decode(&encode(&msg).unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    /// A member leaving says nothing about ownership: the field is the
    /// owner's only, and defaults to false.
    #[test]
    fn leave_group_without_a_transfer_field_parses() {
        let frame = format!(r#"{{"type":"leave_group","conv_id":"{}"}}"#, Uuid::new_v4());
        let msg: ClientMsg = decode(&frame).unwrap();
        let ClientMsg::LeaveGroup {
            transfer_ownership, ..
        } = msg
        else {
            panic!("not a leave_group frame");
        };
        assert!(!transfer_ownership);
    }

    /// Every administration frame through the same encode/decode path, one
    /// broken shape is enough to fail the test.
    #[test]
    fn roundtrip_group_administration() {
        let conv = Uuid::new_v4();
        let frames = vec![
            ClientMsg::GroupAddMember {
                conv_id: conv,
                target_user_id: 7,
            },
            ClientMsg::GroupRemoveMember {
                conv_id: conv,
                target_user_id: 7,
            },
            ClientMsg::GroupSetAdmin {
                conv_id: conv,
                target_user_id: 7,
                rights: AdminRights {
                    ban_users: true,
                    ..AdminRights::default()
                },
            },
            ClientMsg::RenameGroup {
                conv_id: conv,
                title: "Новое название".into(),
            },
            ClientMsg::LeaveGroup {
                conv_id: conv,
                transfer_ownership: true,
            },
            ClientMsg::JoinGroup { conv_id: conv },
            ClientMsg::DeleteGroup { conv_id: conv },
        ];
        for msg in frames {
            let back: ClientMsg = decode(&encode(&msg).unwrap()).unwrap();
            assert_eq!(back, msg);
        }
    }

    /// A register frame from before invitations existed has no
    /// `invite_code` and must still parse.
    #[test]
    fn register_without_an_invite_code_parses() {
        let old_frame = r#"{"type":"auth","protocol_version":4,"method":{"kind":"register","login":"a","password":"b"}}"#;
        let msg: ClientMsg = decode(old_frame).unwrap();
        let ClientMsg::Auth {
            method: AuthMethod::Register { invite_code, .. },
            ..
        } = msg
        else {
            panic!("not a register frame");
        };
        assert_eq!(invite_code, None);
    }

    #[test]
    fn register_with_an_invite_code_roundtrips() {
        let msg = ClientMsg::Auth {
            protocol_version: PROTOCOL_VERSION,
            method: AuthMethod::Register {
                login: "alice".into(),
                password: "p@ss w0rd!".into(),
                invite_code: Some("ABCD2345".into()),
            },
        };
        let line = encode(&msg).unwrap();
        assert!(line.contains("invite_code"));
        let back: ClientMsg = decode(&line).unwrap();
        assert_eq!(back, msg);
    }

    /// Without a code the field is absent rather than null, so the frame is
    /// byte-identical to what a client before invitations used to send.
    #[test]
    fn register_without_a_code_serializes_like_it_used_to() {
        let msg = ClientMsg::Auth {
            protocol_version: PROTOCOL_VERSION,
            method: AuthMethod::Register {
                login: "alice".into(),
                password: "p@ss w0rd!".into(),
                invite_code: None,
            },
        };
        let line = encode(&msg).unwrap();
        assert!(!line.contains("invite_code"));
    }

    #[test]
    fn roundtrip_auth_login() {
        let msg = ClientMsg::Auth {
            protocol_version: PROTOCOL_VERSION,
            method: AuthMethod::Login {
                login: "alice".into(),
                password: "p@ss w0rd!".into(),
            },
        };
        let line = encode(&msg).unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        let back: ClientMsg = decode(&line).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn newline_and_unicode_survive() {
        let msg = ServerMsg::RecvMsg {
            message_id: Uuid::new_v4(),
            conv_id: Uuid::new_v4(),
            sender_user_id: 1234567,
            timestamp: 1730000000,
            content: "строка1\nстрока2\t😀 \"кавычки\"".into(),
        };
        let line = encode(&msg).unwrap();
        assert_eq!(line.matches('\n').count(), 1);
        let back: ServerMsg = decode(&line).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn unknown_type_is_rejected() {
        let result: Result<ClientMsg, _> = decode(r#"{"type":"mind_control","x":1}"#);
        assert!(result.is_err());
    }

    #[test]
    fn crlf_tolerated() {
        let msg = ServerMsg::UserNotFound;
        let line = encode(&msg).unwrap();
        let with_crlf = format!("{line}\r");
        let back: ServerMsg = decode(&with_crlf).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn history_msg_carries_read_state_and_conversation() {
        let conv_id = Uuid::new_v4();
        let msg = ServerMsg::HistoryMsg {
            message_id: Uuid::new_v4(),
            conv_id,
            sender_user_id: 7654321,
            timestamp: 1730000001,
            content: "прочитано".into(),
            is_read: true,
        };
        let back: ServerMsg = decode(&encode(&msg).unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn roundtrip_pow_solution() {
        let msg = ClientMsg::PowSolution { nonce: 987_654_321 };
        let back: ClientMsg = decode(&encode(&msg).unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    /// The wire format is a public contract, renaming a JSON field silently
    /// breaks clients that were built against an older version.
    #[test]
    fn wire_tags_are_stable() {
        let line = encode(&ServerMsg::DmResolved {
            conv_id: Uuid::nil(),
            peer: UserBrief {
                user_id: 42,
                login: "bob".into(),
            },
        })
        .unwrap();
        assert!(line.contains(r#""type":"dm_resolved""#), "{line}");
        assert!(line.contains(r#""conv_id""#), "{line}");
        assert!(line.contains(r#""user_id":42"#), "{line}");

        let line = encode(&ClientMsg::ResolveDm { peer_user_id: 42 }).unwrap();
        assert!(line.contains(r#""type":"resolve_dm""#), "{line}");
        assert!(line.contains(r#""peer_user_id":42"#), "{line}");
    }

    #[test]
    fn error_code_survives_roundtrip_with_payload() {
        let msg = ServerMsg::Error {
            code: ErrorCode::UnsupportedProtocolVersion { server_version: 2 },
            detail: Some("client sent v1".into()),
        };
        let back: ServerMsg = decode(&encode(&msg).unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn error_code_is_tagged_internally() {
        let line = encode(&ServerMsg::Error {
            code: ErrorCode::NotAMember,
            detail: None,
        })
        .unwrap();
        // Nested tag, the frame tag is "type", the error tag is "code".
        assert!(line.contains(r#""type":"error""#), "{line}");
        assert!(line.contains(r#""code":"not_a_member""#), "{line}");
    }

    #[test]
    fn every_error_code_has_a_message() {
        let codes = [
            ErrorCode::UnsupportedProtocolVersion { server_version: 2 },
            ErrorCode::InvalidCredentials,
            ErrorCode::RegistrationFailed,
            ErrorCode::MustChangePassword,
            ErrorCode::MalformedFrame,
            ErrorCode::NotAMember,
            ErrorCode::NoPendingRequest,
            ErrorCode::AlreadyFriends,
            ErrorCode::CannotTargetYourself,
            ErrorCode::ConversationNotFound,
            ErrorCode::UserNotFound,
            ErrorCode::MessageTooLong,
            ErrorCode::Internal,
        ];
        for code in codes {
            assert!(!code.to_string().is_empty(), "missing Display for {code:?}");
        }
    }

    /// A client must be able to tell the codes apart without parsing text,
    /// this is the whole point of replacing `reason: String`.
    #[test]
    fn error_codes_are_distinguishable() {
        let not_member = ServerMsg::Error {
            code: ErrorCode::NotAMember,
            detail: None,
        };
        let too_long = ServerMsg::Error {
            code: ErrorCode::MessageTooLong,
            detail: None,
        };
        assert_ne!(not_member, too_long);
    }
}
