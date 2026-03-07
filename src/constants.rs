// Wire protocol version
pub const VERSION: u8 = 1;
pub const PROTO_CLIENT: u8 = 0x00;
pub const SERVER_PORT: u16 = 42;

// Command codes
pub const CMD_GET_NONCE: u8 = 0x01;
pub const CMD_AUTH: u8 = 0x02;
pub const CMD_PING: u8 = 0x03;
pub const CMD_CREATE_CHAT: u8 = 0x10;
pub const CMD_DELETE_CHAT: u8 = 0x11;
pub const CMD_UPDATE_CHAT_INFO: u8 = 0x12;
pub const CMD_ADD_USER: u8 = 0x20;
pub const CMD_DELETE_USER: u8 = 0x21;
pub const CMD_LEAVE_CHAT: u8 = 0x22;
pub const CMD_GET_USER_CHATS: u8 = 0x23;
pub const CMD_SEND_MESSAGE: u8 = 0x30;
pub const CMD_DELETE_MESSAGE: u8 = 0x31;
pub const CMD_GOT_MESSAGE: u8 = 0x32;
pub const CMD_GET_LAST_MESSAGE_ID: u8 = 0x33;
pub const CMD_SUBSCRIBE: u8 = 0x35;
pub const CMD_GET_MESSAGES_SINCE: u8 = 0x36;
pub const CMD_SEND_INVITE: u8 = 0x40;
pub const CMD_GOT_INVITE: u8 = 0x41;
pub const CMD_INVITE_RESPONSE: u8 = 0x42;
pub const CMD_UPDATE_MEMBER_INFO: u8 = 0x50;
pub const CMD_REQUEST_MEMBER_INFO: u8 = 0x51;
pub const CMD_GET_MEMBERS_INFO: u8 = 0x52;
pub const CMD_GET_MEMBERS: u8 = 0x53;
pub const CMD_GOT_MEMBER_INFO: u8 = 0x54;
pub const CMD_CHANGE_MEMBER_STATUS: u8 = 0x55;

// Response status
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR: u8 = 0x01;
pub const STATUS_PUSH: u8 = 0x02;

// System event codes
pub const SYS_USER_ADDED: u8 = 0x01;
pub const SYS_USER_LEFT: u8 = 0x03;
pub const SYS_USER_BANNED: u8 = 0x04;
pub const SYS_CHAT_DELETED: u8 = 0x05;
pub const SYS_CHAT_INFO_CHANGE: u8 = 0x06;
pub const SYS_PERMS_CHANGED: u8 = 0x07;
pub const SYS_MESSAGE_DELETED: u8 = 0x08;
pub const SYS_MEMBER_ONLINE: u8 = 0x09;

// Limits
pub const MAX_NAME_LEN: usize = 25;
pub const MAX_DESC_LEN: usize = 200;
pub const MAX_AVATAR_BYTES: usize = 200 * 1024;
pub const MAX_PAYLOAD: u32 = 32 << 20; // 32 MB

// File names
pub const DB_FILE: &str = "mediator.db";
pub const KEY_FILE: &str = "mediator.key";
