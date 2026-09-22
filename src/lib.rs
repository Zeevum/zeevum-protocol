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
use uuid::Uuid;

pub mod pow;

/// Bumped on every breaking change to the message types. Renaming a field,
/// changing a type, removing a variant. Adding a variant breaks older receivers
/// too, so it counts as breaking as well.
pub const PROTOCOL_VERSION: u32 = 2;
pub const MAX_LOGIN_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 4096;
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
            Self::MalformedFrame => write!(f, "Malformed frame"),
            Self::NotAMember => write!(f, "You are not a member of this conversation"),
            Self::NotFriends => write!(f, "You are not friends with this user"),
            Self::NoPendingRequest => write!(f, "No pending friend request from this user"),
            Self::AlreadyFriends => write!(f, "Already friends"),
            Self::CannotTargetYourself => write!(f, "Cannot target yourself"),
            Self::ConversationNotFound => write!(f, "Conversation not found"),
            Self::UserNotFound => write!(f, "User not found"),
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
    /// `all_sessions` also drops every other session of the user. The server
    /// closes the connection either way
    Logout {
        all_sessions: bool,
    },
}

/// Registration additionally requires proof of work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    Token { token: String },
    Login { login: String, password: String },
    Register { login: String, password: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Sent before registration is processed.
    PowChallenge {
        challenge: String,
        difficulty_bits: u32,
    },
    AuthOk {
        user_id: UserId,
        token: String,
        expires_at: i64,
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

#[cfg(test)]
mod tests {
    use super::*;

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
