use crate::client::ClientConn;
use crate::db::*;
use crate::permissions::*;
use crate::constants::*;
use crate::server::*;
use crate::tlv::*;
use ed25519_dalek::Verifier;
use std::io::Write;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Dispatch a command to the appropriate handler.
pub async fn dispatch(state: &Arc<ServerState>, cc: &Arc<ClientConn>, cmd: u8, req_id: u16, payload: &[u8]) {
    match cmd {
        CMD_GET_NONCE => handle_get_nonce(state, cc, req_id, payload).await,
        CMD_AUTH => handle_auth(state, cc, req_id, payload).await,
        CMD_PING => handle_ping(cc, req_id).await,
        CMD_CREATE_CHAT => handle_create_chat(state, cc, req_id, payload).await,
        CMD_DELETE_CHAT => handle_delete_chat(state, cc, req_id, payload).await,
        CMD_UPDATE_CHAT_INFO => handle_update_chat_info(state, cc, req_id, payload).await,
        CMD_ADD_USER => handle_add_user(state, cc, req_id, payload).await,
        CMD_DELETE_USER => handle_delete_user(state, cc, req_id, payload).await,
        CMD_GET_USER_CHATS => handle_get_user_chats(state, cc, req_id, payload).await,
        CMD_LEAVE_CHAT => handle_leave_chat(state, cc, req_id, payload).await,
        CMD_SUBSCRIBE => handle_subscribe(state, cc, req_id, payload).await,
        CMD_GET_MESSAGES_SINCE => handle_get_messages_since(state, cc, req_id, payload).await,
        CMD_SEND_MESSAGE => handle_send_message(state, cc, req_id, payload).await,
        CMD_DELETE_MESSAGE => handle_delete_message(state, cc, req_id, payload).await,
        CMD_GET_LAST_MESSAGE_ID => handle_get_last_message_id(state, cc, req_id, payload).await,
        CMD_SEND_INVITE => handle_send_invite(state, cc, req_id, payload).await,
        CMD_INVITE_RESPONSE => handle_invite_response(state, cc, req_id, payload).await,
        CMD_UPDATE_MEMBER_INFO => handle_update_member_info(state, cc, req_id, payload).await,
        CMD_GET_MEMBERS_INFO => handle_get_members_info(state, cc, req_id, payload).await,
        CMD_GET_MEMBERS => handle_get_members(state, cc, req_id, payload).await,
        CMD_CHANGE_MEMBER_STATUS => handle_change_member_status(state, cc, req_id, payload).await,
        _ => {
            let _ = cc.write_err(req_id, "unknown cmd").await;
        }
    }
}

// ---- Helper: lookup permissions ----

async fn lookup_perms(conn: &turso::Connection, chat_id: i64, pub_key: &[u8]) -> Option<(u8, bool)> {
    let users_tbl = format!("users-{}", chat_id);
    let q = format!("SELECT perms_flags, banned FROM \"{}\" WHERE pubkey=?1", users_tbl);
    let mut rows = match conn.query(&q, turso::params![pub_key]).await {
        Ok(r) => r,
        Err(_) => return None,
    };
    match rows.next().await {
        Ok(Some(row)) => {
            let perms: i64 = row.get(0).unwrap_or(0);
            let banned: i64 = row.get(1).unwrap_or(0);
            Some((perms as u8, banned != 0))
        }
        _ => None,
    }
}

// ---- Auth handlers ----

async fn handle_get_nonce(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let pk = match tlv_get_bytes(&tlvs, TAG_PUBKEY, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid pubkey").await; return; }
    };

    let nonce = rand32();
    let now = now_unix();

    {
        let _guard = state.db.write_mu.lock().await;
        if let Err(e) = cc.db_conn.execute(
            "INSERT INTO nonces(pubkey, nonce, ts) VALUES(?1,?2,?3)
             ON CONFLICT(pubkey) DO UPDATE SET nonce=excluded.nonce, ts=excluded.ts",
            turso::params![pk, nonce.as_slice(), now],
        ).await {
            error!("handleGetNonce: db error: {}", e);
            let _ = cc.write_err(req_id, "db error inserting nonce").await;
            return;
        }
    }

    let resp = match build_tlv_payload(|w| tlv_encode_bytes(w, TAG_NONCE, &nonce)) {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "tlv encode error").await; return; }
    };
    let _ = cc.write_ok(req_id, &resp).await;
}

async fn handle_auth(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let rawpk = match tlv_get_bytes(&tlvs, TAG_PUBKEY, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid pubkey").await; return; }
    };
    let nonce = match tlv_get_bytes(&tlvs, TAG_NONCE, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid nonce").await; return; }
    };
    let sig = match tlv_get_bytes(&tlvs, TAG_SIGNATURE, 64) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid signature").await; return; }
    };

    let mut pk = [0u8; 32];
    pk.copy_from_slice(rawpk);

    // Check nonce (hold write_mu to avoid concurrent access issues with turso Connection)
    let db_nonce: Vec<u8> = {
        let _guard = state.db.write_mu.lock().await;
        let q = "SELECT nonce FROM nonces WHERE pubkey = ?1";
        let mut rows = match cc.db_conn.query(q, turso::params![pk.as_slice()]).await {
            Ok(r) => r,
            Err(e) => {
                warn!("handle_auth: nonce query error: {}", e);
                let _ = cc.write_err(req_id, "db error").await;
                return;
            }
        };
        match rows.next().await {
            Ok(Some(row)) => row.get::<Vec<u8>>(0).unwrap_or_default(),
            Ok(None) => { let _ = cc.write_err(req_id, "unknown nonce").await; return; }
            Err(e) => {
                warn!("handle_auth: nonce row read error: {}", e);
                let _ = cc.write_err(req_id, &format!("db read error: {}", e)).await;
                return;
            }
        }
    };

    if !equal_bytes(&db_nonce, nonce) {
        let _ = cc.write_err(req_id, "nonce mismatch").await;
        return;
    }

    // Verify Ed25519 signature
    let verify_key = match ed25519_dalek::VerifyingKey::from_bytes(&pk) {
        Ok(k) => k,
        Err(_) => { let _ = cc.write_err(req_id, "invalid pubkey").await; return; }
    };
    let signature = match ed25519_dalek::Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => { let _ = cc.write_err(req_id, "invalid signature").await; return; }
    };
    if verify_key.verify(nonce, &signature).is_err() {
        let _ = cc.write_err(req_id, "invalid signature").await;
        return;
    }

    // Delete used nonce
    {
        let _guard = state.db.write_mu.lock().await;
        let _ = cc.db_conn.execute("DELETE FROM nonces WHERE pubkey=?1", turso::params![pk.as_slice()]).await;
    }

    debug!("user {} authenticated", hex::encode(&pk[..4]));

    {
        *cc.authed.write().await = true;
        *cc.pub_key.write().await = pk;
    }

    // Address-based deduplication
    let addr = cc.addr.clone();
    let addr_key = get_addr_key(&pk, &addr);

    {
        let mut auth = state.auth_clients.write().await;
        let mut addr_map = state.addr_conn_map.write().await;

        // Kill old connection from same pubkey+address
        if let Some(&old_id) = addr_map.get(&addr_key) {
            debug!("duplicate connection from {} for user {}, closing old", addr, hex::encode(&pk[..4]));
            if let Some(conns) = auth.get_mut(&pk) {
                conns.remove(&old_id);
            }
            addr_map.remove(&addr_key);

            // Close old connection
            let clients = state.clients.read().await;
            if let Some(old_client) = clients.get(&old_id) {
                let old = old_client.clone();
                tokio::spawn(async move { old.conn.close().await; });
            }
        }

        auth.entry(pk).or_default().insert(cc.id);
        addr_map.insert(addr_key, cc.id);
    }

    let _ = cc.write_ok(req_id, &[]).await;

    // Send pending invites (uses its own DB connection to avoid racing with the command loop)
    let state2 = state.clone();
    let cc2 = cc.clone();
    tokio::spawn(async move {
        match state2.db.connect() {
            Ok(conn) => send_pending_invites(&state2, &cc2, &conn).await,
            Err(e) => warn!("send_pending_invites: failed to connect: {}", e),
        }
    });
}

async fn handle_ping(cc: &Arc<ClientConn>, req_id: u16) {
    let _ = cc.write_ok(req_id, &[]).await;
}

// ---- Chat handlers ----

async fn handle_create_chat(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "not authenticated").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let rawpk = match tlv_get_bytes(&tlvs, TAG_PUBKEY, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid owner pubkey").await; return; }
    };
    let cc_pub = *cc.pub_key.read().await;
    if !equal_bytes(rawpk, &cc_pub) {
        let _ = cc.write_err(req_id, "keys mismatch").await;
        return;
    }

    let nonce = match tlv_get_bytes(&tlvs, TAG_NONCE, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid nonce").await; return; }
    };
    let counter = match tlv_get_bytes(&tlvs, TAG_COUNTER, 4) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid counter").await; return; }
    };
    let sig = match tlv_get_bytes(&tlvs, TAG_SIGNATURE, 64) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid signature").await; return; }
    };
    let name = match tlv_get_string(&tlvs, TAG_CHAT_NAME) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing chat name").await; return; }
    };
    let desc = match tlv_get_string(&tlvs, TAG_CHAT_DESC) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing chat description").await; return; }
    };
    let avatar = tlv_get_bytes_optional(&tlvs, TAG_CHAT_AVATAR);

    // Validate lengths (character count, not bytes)
    if name.chars().count() > MAX_NAME_LEN || desc.chars().count() > MAX_DESC_LEN {
        let _ = cc.write_err(req_id, "field too large").await;
        return;
    }
    if let Some(av) = avatar {
        if av.len() > MAX_AVATAR_BYTES {
            let _ = cc.write_err(req_id, "field too large").await;
            return;
        }
    }

    // Verify nonce from DB
    let q = "SELECT nonce FROM nonces WHERE pubkey=?1";
    let mut rows = match cc.db_conn.query(q, turso::params![cc_pub.as_slice()]).await {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "db error").await; return; }
    };
    let db_nonce: Vec<u8> = match rows.next().await {
        Ok(Some(row)) => row.get::<Vec<u8>>(0).unwrap_or_default(),
        _ => { let _ = cc.write_err(req_id, "unknown nonce").await; return; }
    };
    drop(rows);

    if !equal_bytes(&db_nonce, nonce) {
        let _ = cc.write_err(req_id, "unknown nonce").await;
        return;
    }

    // Signature filter + verification
    if sig.len() != 64 || sig[0] != 0 || sig[1] != 0 {
        let _ = cc.write_err(req_id, "signature filter failed").await;
        return;
    }
    let mut msg = Vec::with_capacity(nonce.len() + counter.len());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(counter);

    let verify_key = match ed25519_dalek::VerifyingKey::from_bytes(&cc_pub) {
        Ok(k) => k,
        Err(_) => { let _ = cc.write_err(req_id, "invalid pubkey").await; return; }
    };
    let signature = match ed25519_dalek::Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => { let _ = cc.write_err(req_id, "invalid signature").await; return; }
    };
    if verify_key.verify(&msg, &signature).is_err() {
        let _ = cc.write_err(req_id, "invalid signature").await;
        return;
    }

    // Delete used nonce
    {
        let _guard = state.db.write_mu.lock().await;
        let _ = cc.db_conn.execute("DELETE FROM nonces WHERE pubkey=?1", turso::params![cc_pub.as_slice()]).await;
    }

    // Generate chat ID
    let mut b = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut b);
    let chat_id = (i64::from_be_bytes(b)) & i64::MAX;
    let chat_id = if chat_id == 0 { 1 } else { chat_id };

    let now = now_unix();

    // Serialized writes (write_mu held throughout)
    {
        let _guard = state.db.write_mu.lock().await;

        if let Err(_) = cc.db_conn.execute(
            "INSERT INTO chats(id, owner_pubkey, created_at) VALUES(?1,?2,?3)",
            turso::params![chat_id, cc_pub.as_slice(), now],
        ).await {
            let _ = cc.write_err(req_id, "db chat meta").await;
            return;
        }

        if let Err(_) = state.db.create_chat_tables(&cc.db_conn, chat_id).await {
            let _ = cc.write_err(req_id, "db create tables").await;
            return;
        }

        let sett = format!("settings-{}", chat_id);
        let avatar_val: Option<&[u8]> = avatar;
        if let Err(_) = cc.db_conn.execute(
            &format!("INSERT INTO \"{}\"(name, description, avatar, perms_flags, created_at, extra) VALUES(?1,?2,?3,?4,?5,NULL)", sett),
            turso::params![name.as_str(), desc.as_str(), avatar_val, 0i64, now],
        ).await {
            let _ = cc.write_err(req_id, "db settings").await;
            return;
        }

        let users = format!("users-{}", chat_id);
        let owner_perms = (PERM_OWNER | PERM_USER) as i64;
        let empty_info: Option<&[u8]> = None;
        if let Err(_) = cc.db_conn.execute(
            &format!("INSERT INTO \"{}\"(pubkey, text_rank, perms_flags, accepted_at, changed_at, banned, info) VALUES(?1,?2,?3,?4,?5,0,?6)", users),
            turso::params![cc_pub.as_slice(), "", owner_perms, now, 0i64, empty_info],
        ).await {
            let _ = cc.write_err(req_id, "db owner").await;
            return;
        }
    }

    let resp = match build_tlv_payload(|w| tlv_encode_i64(w, TAG_CHAT_ID, chat_id)) {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "tlv encode error").await; return; }
    };
    let _ = cc.write_ok(req_id, &resp).await;
}

async fn handle_delete_chat(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };

    // Check owner
    let q = "SELECT owner_pubkey FROM chats WHERE id=?1";
    let mut rows = match cc.db_conn.query(q, turso::params![chat_id]).await {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "db error").await; return; }
    };
    let stored_owner: Vec<u8> = match rows.next().await {
        Ok(Some(row)) => row.get::<Vec<u8>>(0).unwrap_or_default(),
        _ => { let _ = cc.write_err(req_id, "no such chat").await; return; }
    };
    drop(rows);

    let cc_pub = *cc.pub_key.read().await;
    if !cc.is_authed().await || !equal_bytes(&stored_owner, &cc_pub) {
        let _ = cc.write_err(req_id, "not an owner").await;
        return;
    }

    let (sett, users, msgs) = chat_table_names(chat_id);
    {
        let _guard = state.db.write_mu.lock().await;
        let _ = cc.db_conn.execute(&format!("DROP TABLE IF EXISTS \"{}\"", sett), ()).await;
        let _ = cc.db_conn.execute(&format!("DROP TABLE IF EXISTS \"{}\"", users), ()).await;
        let _ = cc.db_conn.execute(&format!("DROP TABLE IF EXISTS \"{}\"", msgs), ()).await;
        let _ = cc.db_conn.execute("DELETE FROM chats WHERE id=?1", turso::params![chat_id]).await;
    }

    // Broadcast system message: chat deleted
    let ts = now_unix();
    let mut body = vec![0u8; 1 + 32 + 32];
    body[0] = SYS_CHAT_DELETED;
    body[1..33].copy_from_slice(&cc_pub);
    body[33..65].copy_from_slice(&rand32());

    let guid = generate_message_guid(ts, &body);
    let broadcast_payload = build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_CHAT_ID, chat_id)?;
        tlv_encode_i64(w, TAG_MESSAGE_ID, 0)?;
        tlv_encode_i64(w, TAG_MESSAGE_GUID, guid)?;
        tlv_encode_i64(w, TAG_TIMESTAMP, ts)?;
        tlv_encode_bytes(w, TAG_PUBKEY, &state.mediator_pub)?;
        tlv_encode_bytes(w, TAG_MESSAGE_BLOB, &body)
    }).unwrap_or_default();

    let sender_id = Some(cc.id);
    state.broadcast_to_chat(chat_id, sender_id, CMD_GOT_MESSAGE as u16, broadcast_payload).await;

    // Unsubscribe from chat
    {
        let mut subs = state.chat_subs.write().await;
        if let Some(set) = subs.get_mut(&chat_id) {
            set.remove(&cc.id);
            if set.is_empty() {
                subs.remove(&chat_id);
            }
        }
    }
    {
        let mut chats = cc.chats.write().await;
        chats.remove(&chat_id);
    }

    let _ = cc.write_ok(req_id, &[1]).await;
}

async fn handle_update_chat_info(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };

    let has_name = tlvs.contains_key(&TAG_CHAT_NAME);
    let has_desc = tlvs.contains_key(&TAG_CHAT_DESC);
    let has_avatar = tlvs.contains_key(&TAG_CHAT_AVATAR);

    if !has_name && !has_desc && !has_avatar {
        let _ = cc.write_err(req_id, "no fields to update").await;
        return;
    }

    if has_name {
        let name = String::from_utf8_lossy(tlvs.get(&TAG_CHAT_NAME).unwrap());
        if name.chars().count() > MAX_NAME_LEN {
            let _ = cc.write_err(req_id, "name too long").await;
            return;
        }
    }
    if has_desc {
        let desc = String::from_utf8_lossy(tlvs.get(&TAG_CHAT_DESC).unwrap());
        if desc.chars().count() > MAX_DESC_LEN {
            let _ = cc.write_err(req_id, "description too long").await;
            return;
        }
    }
    if has_avatar && tlvs.get(&TAG_CHAT_AVATAR).unwrap().len() > MAX_AVATAR_BYTES {
        let _ = cc.write_err(req_id, "avatar too large").await;
        return;
    }

    let cc_pub = *cc.pub_key.read().await;
    let perms = lookup_perms(&cc.db_conn,chat_id, &cc_pub).await;
    match perms {
        Some((role, false)) if has_any(role, PERM_OWNER | PERM_ADMIN) => {}
        Some((_, true)) => { let _ = cc.write_err(req_id, "banned").await; return; }
        Some(_) => { let _ = cc.write_err(req_id, "insufficient perms").await; return; }
        None => { let _ = cc.write_err(req_id, "not a member").await; return; }
    }

    // Build dynamic UPDATE
    let sett_tbl = format!("settings-{}", chat_id);
    let mut set_clauses = Vec::new();
    let mut args: Vec<turso::Value> = Vec::new();
    let mut param_idx = 1;

    if has_name {
        set_clauses.push(format!("name=?{}", param_idx));
        args.push(turso::Value::Text(String::from_utf8_lossy(tlvs.get(&TAG_CHAT_NAME).unwrap()).into_owned()));
        param_idx += 1;
    }
    if has_desc {
        set_clauses.push(format!("description=?{}", param_idx));
        args.push(turso::Value::Text(String::from_utf8_lossy(tlvs.get(&TAG_CHAT_DESC).unwrap()).into_owned()));
        param_idx += 1;
    }
    if has_avatar {
        set_clauses.push(format!("avatar=?{}", param_idx));
        args.push(turso::Value::Blob(tlvs.get(&TAG_CHAT_AVATAR).unwrap().clone()));
    }

    let query = format!("UPDATE \"{}\" SET {}", sett_tbl, set_clauses.join(", "));
    {
        let _guard = state.db.write_mu.lock().await;
        if let Err(e) = cc.db_conn.execute(&query, args).await {
            error!("updating chat info for chat {}: {}", chat_id, e);
            let _ = cc.write_err(req_id, "db error").await;
            return;
        }
    }

    // Build system message body
    let now = now_unix();
    let sys_body = build_tlv_payload(|w| {
        w.write_all(&[SYS_CHAT_INFO_CHANGE])?;
        tlv_encode_bytes(w, TAG_PUBKEY, &cc_pub)?;
        if has_name { tlv_encode_bytes(w, TAG_CHAT_NAME, tlvs.get(&TAG_CHAT_NAME).unwrap())?; }
        if has_desc { tlv_encode_bytes(w, TAG_CHAT_DESC, tlvs.get(&TAG_CHAT_DESC).unwrap())?; }
        if has_avatar { tlv_encode_bytes(w, TAG_CHAT_AVATAR, tlvs.get(&TAG_CHAT_AVATAR).unwrap())?; }
        Ok(())
    }).unwrap_or_default();

    if let Err(e) = broadcast_system_message(state, &cc.db_conn, chat_id, &sys_body, None, now, true).await {
        error!("broadcasting chat info change: {}", e);
        let _ = cc.write_err(req_id, "broadcast error").await;
        return;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

// ---- User management handlers ----

async fn handle_add_user(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let new_user = match tlv_get_bytes(&tlvs, TAG_USER_PUBKEY, 32) {
        Ok(v) => v.to_vec(),
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid user pubkey").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((role, false)) if has_any(role, PERM_OWNER | PERM_ADMIN | PERM_MOD) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let users_tbl = format!("users-{}", chat_id);
    let now = now_unix();
    let user_perms = PERM_USER as i64;
    let empty_info: Option<&[u8]> = None;

    {
        let _guard = state.db.write_mu.lock().await;
        if let Err(_) = cc.db_conn.execute(
            &format!("INSERT INTO \"{}\"(pubkey, text_rank, perms_flags, accepted_at, changed_at, banned, info) VALUES(?1,?2,?3,?4,?5,0,?6) ON CONFLICT(pubkey) DO UPDATE SET banned=0, perms_flags=excluded.perms_flags", users_tbl),
            turso::params![new_user.as_slice(), "", user_perms, now, now, empty_info],
        ).await {
            let _ = cc.write_err(req_id, "db error").await;
            return;
        }
    }

    // System message: user added
    let mut body = vec![0u8; 1 + 32 + 32 + 32];
    body[0] = SYS_USER_ADDED;
    body[1..33].copy_from_slice(&new_user);
    body[33..65].copy_from_slice(&cc_pub);
    body[65..97].copy_from_slice(&rand32());

    if let Err(e) = broadcast_system_message(state, &cc.db_conn, chat_id, &body, Some(cc.id), now, true).await {
        error!("{}", e);
        let _ = cc.write_err(req_id, "db error").await;
        return;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

async fn handle_delete_user(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let user_pk = match tlv_get_bytes(&tlvs, TAG_USER_PUBKEY, 32) {
        Ok(v) => v.to_vec(),
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid user pubkey").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((role, false)) if has_any(role, PERM_OWNER | PERM_ADMIN | PERM_MOD) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let users_tbl = format!("users-{}", chat_id);
    let now = now_unix();
    {
        let _guard = state.db.write_mu.lock().await;
        let _ = cc.db_conn.execute(
            &format!("UPDATE \"{}\" SET banned=1, perms_flags=(perms_flags | ?1), changed_at=?2 WHERE pubkey=?3", users_tbl),
            turso::params![PERM_BANNED as i64, now, user_pk.as_slice()],
        ).await;
    }

    let mut body = vec![0u8; 1 + 32 + 32 + 32];
    body[0] = SYS_USER_BANNED;
    body[1..33].copy_from_slice(&user_pk);
    body[33..65].copy_from_slice(&cc_pub);
    body[65..97].copy_from_slice(&rand32());

    if let Err(e) = broadcast_system_message(state, &cc.db_conn, chat_id, &body, Some(cc.id), now, true).await {
        error!("{}", e);
        let _ = cc.write_err(req_id, "db error deleting user").await;
        return;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

async fn handle_leave_chat(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((role, _)) if has_any(role, PERM_OWNER) => {
            let _ = cc.write_err(req_id, "owner can't leave").await;
            return;
        }
        Some((_, true)) => { let _ = cc.write_err(req_id, "banned user").await; return; }
        Some(_) => {}
        None => { let _ = cc.write_err(req_id, "not a member").await; return; }
    }

    // Unsubscribe
    {
        let mut subs = state.chat_subs.write().await;
        if let Some(set) = subs.get_mut(&chat_id) {
            set.remove(&cc.id);
            if set.is_empty() { subs.remove(&chat_id); }
        }
    }
    { cc.chats.write().await.remove(&chat_id); }

    let mut body = vec![0u8; 1 + 32 + 32];
    body[0] = SYS_USER_LEFT;
    body[1..33].copy_from_slice(&cc_pub);
    body[33..65].copy_from_slice(&rand32());

    let now = now_unix();
    if let Err(e) = broadcast_system_message(state, &cc.db_conn, chat_id, &body, Some(cc.id), now, true).await {
        error!("{}", e);
        let _ = cc.write_err(req_id, "db error").await;
        return;
    }

    let users_tbl = format!("users-{}", chat_id);
    {
        let _guard = state.db.write_mu.lock().await;
        let _ = cc.db_conn.execute(
            &format!("DELETE FROM \"{}\" WHERE pubkey=?1", users_tbl),
            turso::params![cc_pub.as_slice()],
        ).await;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

async fn handle_get_user_chats(_state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, _p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let mut rows = match cc.db_conn.query("SELECT id FROM chats", ()).await {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "db error").await; return; }
    };

    // Collect all chat IDs first to avoid nested queries on the same connection
    let mut all_ids = Vec::new();
    while let Ok(Some(row)) = rows.next().await {
        let id: i64 = row.get(0).unwrap_or(0);
        all_ids.push(id);
    }
    drop(rows);

    let cc_pub = *cc.pub_key.read().await;
    let mut chat_ids = Vec::new();
    for id in all_ids {
        let users_tbl = format!("users-{}", id);
        let q = format!("SELECT banned FROM \"{}\" WHERE pubkey=?1", users_tbl);
        match cc.db_conn.query(&q, turso::params![cc_pub.as_slice()]).await {
            Ok(mut r) => {
                if let Ok(Some(row)) = r.next().await {
                    let banned: i64 = row.get(0).unwrap_or(0);
                    if banned == 0 {
                        chat_ids.push(id);
                    }
                }
            }
            Err(_) => continue,
        }
    }

    let resp = build_tlv_payload(|w| {
        tlv_encode_u32(w, TAG_COUNT, chat_ids.len() as u32)?;
        for id in &chat_ids {
            tlv_encode_i64(w, TAG_CHAT_ID, *id)?;
        }
        Ok(())
    }).unwrap_or_default();

    let _ = cc.write_ok(req_id, &resp).await;
}

async fn handle_change_member_status(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let target_pk = match tlv_get_bytes(&tlvs, TAG_USER_PUBKEY, 32) {
        Ok(v) => v.to_vec(),
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid user pubkey").await; return; }
    };
    let new_perms = match tlv_get_u8(&tlvs, TAG_PERMS) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid perms").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    let caller_perms = match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((role, false)) => role,
        Some((_, true)) => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
        None => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    };

    if equal_bytes(&cc_pub, &target_pk) {
        let _ = cc.write_err(req_id, "cannot modify own permissions").await;
        return;
    }

    let target_role = match lookup_perms(&cc.db_conn,chat_id, &target_pk).await {
        Some((role, _)) => role,
        None => { let _ = cc.write_err(req_id, "target user not a member").await; return; }
    };

    let is_owner = has_any(caller_perms, PERM_OWNER);
    let is_admin = has_any(caller_perms, PERM_ADMIN);

    if !is_owner && !is_admin {
        let _ = cc.write_err(req_id, "insufficient perms").await;
        return;
    }
    if !is_owner && has_any(target_role, PERM_OWNER) {
        let _ = cc.write_err(req_id, "cannot modify owner permissions").await;
        return;
    }

    let valid = has_any(new_perms, PERM_OWNER | PERM_ADMIN | PERM_MOD | PERM_USER | PERM_READ_ONLY | PERM_BANNED);
    if !valid {
        let _ = cc.write_err(req_id, "invalid permission flags").await;
        return;
    }

    let users_tbl = format!("users-{}", chat_id);
    let now = now_unix();
    let banned_val: i64 = if has_any(new_perms, PERM_BANNED) { 1 } else { 0 };

    {
        let _guard = state.db.write_mu.lock().await;
        if let Err(e) = cc.db_conn.execute(
            &format!("UPDATE \"{}\" SET perms_flags=?1, banned=?2, changed_at=?3 WHERE pubkey=?4", users_tbl),
            turso::params![new_perms as i64, banned_val, now, target_pk.as_slice()],
        ).await {
            error!("updating member permissions: {}", e);
            let _ = cc.write_err(req_id, "db error").await;
            return;
        }
    }

    let mut body = vec![0u8; 1 + 32 + 1 + 32 + 32];
    body[0] = SYS_PERMS_CHANGED;
    body[1..33].copy_from_slice(&target_pk);
    body[33] = new_perms;
    body[34..66].copy_from_slice(&cc_pub);
    body[66..98].copy_from_slice(&rand32());

    if let Err(e) = broadcast_system_message(state, &cc.db_conn, chat_id, &body, Some(cc.id), now, true).await {
        error!("broadcasting permission change: {}", e);
        let _ = cc.write_err(req_id, "broadcast error").await;
        return;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

// ---- Message handlers ----

async fn handle_subscribe(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((role, false)) if !has_any(role, PERM_READ_ONLY) => {}
        Some((_, true)) => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
        Some(_) => { let _ = cc.write_err(req_id, "read-only user").await; return; }
        None => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let msg_tbl = format!("messages-{}", chat_id);
    let q = format!("SELECT IFNULL(MAX(id),0) FROM \"{}\"", msg_tbl);
    let last_id: i64 = match cc.db_conn.query(&q, ()).await {
        Ok(mut r) => match r.next().await {
            Ok(Some(row)) => row.get(0).unwrap_or(0),
            _ => 0,
        },
        Err(_) => { let _ = cc.write_err(req_id, "db error").await; return; }
    };

    state.subscribe(chat_id, cc.id, cc).await;

    let resp = build_tlv_payload(|w| tlv_encode_u64(w, TAG_MESSAGE_ID, last_id as u64)).unwrap_or_default();
    let _ = cc.write_ok(req_id, &resp).await;

    // Request member info
    let state2 = state.clone();
    let cc2 = cc.clone();
    tokio::spawn(async move {
        match state2.db.connect() {
            Ok(conn) => request_member_info(&cc2, &conn, chat_id).await,
            Err(e) => warn!("request_member_info: failed to connect: {}", e),
        }
    });
}

async fn handle_get_messages_since(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let since_id = match tlv_get_i64(&tlvs, TAG_SINCE_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid since message id").await; return; }
    };
    let limit = match tlv_get_u32(&tlvs, TAG_LIMIT) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid limit").await; return; }
    };
    if limit == 0 || limit > 500 {
        let _ = cc.write_err(req_id, "limit must be between 1 and 500").await;
        return;
    }

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((_, false)) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let msg_tbl = format!("messages-{}", chat_id);
    let q = format!("SELECT id, guid, ts, author FROM \"{}\" WHERE id>?1 ORDER BY id ASC LIMIT ?2", msg_tbl);
    let mut rows = match cc.db_conn.query(&q, turso::params![since_id, limit as i64]).await {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "db error").await; return; }
    };

    struct Msg {
        id: i64,
        guid: i64,
        ts: i64,
        author: Vec<u8>,
        blob: Vec<u8>,
    }

    let mut msgs = Vec::new();
    while let Ok(Some(row)) = rows.next().await {
        let id: i64 = row.get(0).unwrap_or(0);
        let guid: i64 = row.get(1).unwrap_or(0);
        let ts: i64 = row.get(2).unwrap_or(0);
        let author: Vec<u8> = row.get(3).unwrap_or_default();

        let key = format!("{:016x}:{:016x}", chat_id, guid);
        let blob = match state.cache.get(&key).await {
            Some(b) => b,
            None => continue,
        };

        msgs.push(Msg { id, guid, ts, author, blob });
    }

    let resp = build_tlv_payload(|w| {
        tlv_encode_u32(w, TAG_COUNT, msgs.len() as u32)?;
        for m in &msgs {
            tlv_encode_i64(w, TAG_MESSAGE_ID, m.id)?;
            tlv_encode_i64(w, TAG_MESSAGE_GUID, m.guid)?;
            tlv_encode_i64(w, TAG_TIMESTAMP, m.ts)?;
            tlv_encode_bytes(w, TAG_PUBKEY, &m.author)?;
            tlv_encode_bytes(w, TAG_MESSAGE_BLOB, &m.blob)?;
        }
        Ok(())
    }).unwrap_or_default();

    let _ = cc.write_ok(req_id, &resp).await;
}

async fn handle_send_message(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let mut guid = match tlv_get_i64(&tlvs, TAG_MESSAGE_GUID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid guid").await; return; }
    };
    let blob = tlv_get_bytes_optional(&tlvs, TAG_MESSAGE_BLOB).unwrap_or(&[]).to_vec();
    let timestamp = tlv_get_i64(&tlvs, TAG_TIMESTAMP).unwrap_or_else(|_| now_unix());

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((role, false)) if !has_any(role, PERM_READ_ONLY) => {}
        Some((_, true)) => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
        Some(_) => { let _ = cc.write_err(req_id, "read-only user").await; return; }
        None => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let msg_tbl = format!("messages-{}", chat_id);
    let original_guid = guid;
    let mut msg_id: i64 = 0;
    let mut success = false;

    for _attempt in 0..10 {
        let q = format!("INSERT INTO \"{}\"(ts, guid, author) VALUES(?1,?2,?3)", msg_tbl);
        let _guard = state.db.write_mu.lock().await;
        match cc.db_conn.execute(&q, turso::params![timestamp, guid, cc_pub.as_slice()]).await {
            Ok(_) => {
                // Get last insert rowid
                let id_q = format!("SELECT id FROM \"{}\" WHERE guid=?1", msg_tbl);
                if let Ok(mut r) = cc.db_conn.query(&id_q, turso::params![guid]).await {
                    if let Ok(Some(row)) = r.next().await {
                        msg_id = row.get(0).unwrap_or(0);
                    }
                }
                success = true;
                break;
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("UNIQUE constraint failed") {
                    // Check if duplicate or collision
                    let check_q = format!("SELECT id, ts FROM \"{}\" WHERE guid=?1", msg_tbl);
                    if let Ok(mut r) = cc.db_conn.query(&check_q, turso::params![guid]).await {
                        if let Ok(Some(row)) = r.next().await {
                            let existing_id: i64 = row.get(0).unwrap_or(0);
                            let existing_ts: i64 = row.get(1).unwrap_or(0);
                            if existing_ts == timestamp {
                                // Duplicate
                                let resp = build_tlv_payload(|w| {
                                    tlv_encode_i64(w, TAG_MESSAGE_GUID, guid)?;
                                    tlv_encode_i64(w, TAG_MESSAGE_ID, existing_id)
                                }).unwrap_or_default();
                                let _ = cc.write_ok(req_id, &resp).await;
                                return;
                            }
                        }
                    }
                    // Real collision
                    warn!("GUID collision for chat {}, guid={} - incrementing and retrying", chat_id, guid);
                    guid += 1;
                    continue;
                }
                error!("Failed to insert message: {} (guid={}, author={})", e, guid, hex::encode(&cc_pub[..4]));
                let _ = cc.write_err(req_id, "db error").await;
                return;
            }
        }
    }

    if !success {
        error!("GUID collision limit exceeded for chat {} (original guid={})", chat_id, original_guid);
        let _ = cc.write_err(req_id, "db error - guid collision limit exceeded").await;
        return;
    }

    // Store blob in cache
    let key = format!("{:016x}:{:016x}", chat_id, guid);
    state.cache.set(&key, &blob).await;

    // Broadcast
    let broadcast_payload = build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_CHAT_ID, chat_id)?;
        tlv_encode_i64(w, TAG_MESSAGE_ID, msg_id)?;
        tlv_encode_i64(w, TAG_MESSAGE_GUID, guid)?;
        tlv_encode_i64(w, TAG_TIMESTAMP, timestamp)?;
        tlv_encode_bytes(w, TAG_PUBKEY, &cc_pub)?;
        tlv_encode_bytes(w, TAG_MESSAGE_BLOB, &blob)
    }).unwrap_or_default();

    state.broadcast_message(chat_id, Some(cc.id), broadcast_payload).await;

    let resp = build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_MESSAGE_GUID, guid)?;
        tlv_encode_i64(w, TAG_MESSAGE_ID, msg_id)
    }).unwrap_or_default();
    let _ = cc.write_ok(req_id, &resp).await;
}

async fn handle_delete_message(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let guid = match tlv_get_i64(&tlvs, TAG_MESSAGE_GUID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid message guid").await; return; }
    };

    let msg_tbl = format!("messages-{}", chat_id);
    let q = format!("SELECT author FROM \"{}\" WHERE guid=?1", msg_tbl);
    let author: Vec<u8> = match cc.db_conn.query(&q, turso::params![guid]).await {
        Ok(mut r) => match r.next().await {
            Ok(Some(row)) => row.get(0).unwrap_or_default(),
            _ => { let _ = cc.write_err(req_id, "message not found").await; return; }
        },
        Err(_) => { let _ = cc.write_err(req_id, "message not found").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    let is_author = equal_bytes(&author, &cc_pub);

    if !is_author {
        match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
            Some((role, false)) if has_any(role, PERM_OWNER | PERM_ADMIN | PERM_MOD) => {}
            _ => { let _ = cc.write_err(req_id, "insufficient perms").await; return; }
        }
    }

    {
        let _guard = state.db.write_mu.lock().await;
        let _ = cc.db_conn.execute(
            &format!("DELETE FROM \"{}\" WHERE guid=?1", msg_tbl),
            turso::params![guid],
        ).await;
    }

    // System message: message deleted
    let mut body = vec![0u8; 41];
    body[0] = SYS_MESSAGE_DELETED;
    body[1..9].copy_from_slice(&(guid as u64).to_be_bytes());
    body[9..41].copy_from_slice(&cc_pub);

    let now = now_unix();
    if let Err(e) = broadcast_system_message(state, &cc.db_conn, chat_id, &body, None, now, true).await {
        error!("failed to broadcast deletion system message: {}", e);
        let _ = cc.write_err(req_id, "broadcast error").await;
        return;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

async fn handle_get_last_message_id(_state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((_, false)) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let msg_tbl = format!("messages-{}", chat_id);
    let q = format!("SELECT IFNULL(MAX(id),0) FROM \"{}\"", msg_tbl);
    let last_id: i64 = match cc.db_conn.query(&q, ()).await {
        Ok(mut r) => match r.next().await {
            Ok(Some(row)) => row.get(0).unwrap_or(0),
            _ => 0,
        },
        Err(_) => { let _ = cc.write_err(req_id, "db error").await; return; }
    };

    let resp = build_tlv_payload(|w| tlv_encode_u64(w, TAG_MESSAGE_ID, last_id as u64)).unwrap_or_default();
    let _ = cc.write_ok(req_id, &resp).await;
}

// ---- Invite handlers ----

async fn handle_send_invite(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let to_pubkey = match tlv_get_bytes(&tlvs, TAG_USER_PUBKEY, 32) {
        Ok(v) => v.to_vec(),
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid to_pubkey").await; return; }
    };
    let encrypted_data = tlv_get_bytes_optional(&tlvs, TAG_INVITE_DATA).unwrap_or(&[]).to_vec();

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((role, false)) if has_any(role, PERM_OWNER | PERM_ADMIN | PERM_MOD) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    // Check if target is already a member
    if let Some((role, false)) = lookup_perms(&cc.db_conn,chat_id, &to_pubkey).await {
        if has_any(role, PERM_OWNER | PERM_ADMIN | PERM_MOD | PERM_USER | PERM_READ_ONLY) {
            let _ = cc.write_err(req_id, "user already in chat").await;
            return;
        }
    }

    let now = now_unix();
    const ONE_HOUR: i64 = 3600;

    // Check existing invite
    let mut existing_id: Option<i64> = None;
    let mut existing_ts: i64 = 0;
    let q = "SELECT id, timestamp FROM invites WHERE to_pubkey=?1 AND chat_id=?2";
    if let Ok(mut r) = cc.db_conn.query(q, turso::params![to_pubkey.as_slice(), chat_id]).await {
        if let Ok(Some(row)) = r.next().await {
            existing_id = Some(row.get(0).unwrap_or(0));
            existing_ts = row.get(1).unwrap_or(0);
        }
    }

    let invite_id: i64;
    if let Some(eid) = existing_id {
        if now - existing_ts < ONE_HOUR {
            let _ = cc.write_err(req_id, "invite already exists").await;
            return;
        }
        // Update existing
        {
            let _guard = state.db.write_mu.lock().await;
            let _ = cc.db_conn.execute(
                "UPDATE invites SET timestamp=?1, from_pubkey=?2, encrypted_data=?3, sent=0 WHERE id=?4",
                turso::params![now, cc_pub.as_slice(), encrypted_data.as_slice(), eid],
            ).await;
        }
        invite_id = eid;
    } else {
        // Insert new
        let _guard = state.db.write_mu.lock().await;
        if let Err(_) = cc.db_conn.execute(
            "INSERT INTO invites(timestamp, from_pubkey, to_pubkey, chat_id, encrypted_data) VALUES(?1,?2,?3,?4,?5)",
            turso::params![now, cc_pub.as_slice(), to_pubkey.as_slice(), chat_id, encrypted_data.as_slice()],
        ).await {
            let _ = cc.write_err(req_id, "db insert error").await;
            return;
        }
        // Get last insert id
        let mut r = cc.db_conn.query("SELECT last_insert_rowid()", ()).await.unwrap();
        invite_id = if let Ok(Some(row)) = r.next().await { row.get(0).unwrap_or(0) } else { 0 };
    }

    // Send to connected recipients
    let mut to_pub_arr = [0u8; 32];
    to_pub_arr.copy_from_slice(&to_pubkey);

    let recipient_ids: Vec<ClientId> = {
        let auth = state.auth_clients.read().await;
        auth.get(&to_pub_arr).map(|s| s.iter().copied().collect()).unwrap_or_default()
    };

    if !recipient_ids.is_empty() {
        let clients = state.clients.read().await;
        for cid in recipient_ids {
            if let Some(client) = clients.get(&cid) {
                let s = state.clone();
                let c = client.clone();
                let from = cc_pub.to_vec();
                let data = encrypted_data.clone();
                tokio::spawn(async move {
                    match s.db.connect() {
                        Ok(conn) => { send_invite_to_client(&s, &c, &conn, invite_id, now, &from, chat_id, &data).await; }
                        Err(e) => warn!("send_invite_to_client: failed to connect: {}", e),
                    }
                });
            }
        }
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

async fn handle_invite_response(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let invite_id = match tlv_get_i64(&tlvs, TAG_INVITE_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid invite id").await; return; }
    };
    let accepted = match tlv_get_u8(&tlvs, TAG_ACCEPTED) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid accepted flag").await; return; }
    };

    if accepted > 1 {
        let _ = cc.write_err(req_id, "invalid accepted value").await;
        return;
    }

    // Look up invite
    let q = "SELECT chat_id, from_pubkey, to_pubkey FROM invites WHERE id=?1";
    let (chat_id, from_pubkey, to_pubkey): (i64, Vec<u8>, Vec<u8>) = match cc.db_conn.query(q, turso::params![invite_id]).await {
        Ok(mut r) => match r.next().await {
            Ok(Some(row)) => (
                row.get(0).unwrap_or(0),
                row.get(1).unwrap_or_default(),
                row.get(2).unwrap_or_default(),
            ),
            _ => { let _ = cc.write_err(req_id, "invite not found").await; return; }
        },
        Err(_) => { let _ = cc.write_err(req_id, "invite not found").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    if !equal_bytes(&cc_pub, &to_pubkey) {
        let _ = cc.write_err(req_id, "not recipient of this invite").await;
        return;
    }

    if accepted == 1 {
        let users_tbl = format!("users-{}", chat_id);
        let now = now_unix();
        let user_perms = PERM_USER as i64;
        let empty_info: Option<&[u8]> = None;

        {
            let _guard = state.db.write_mu.lock().await;
            if let Err(e) = cc.db_conn.execute(
                &format!("INSERT INTO \"{}\"(pubkey, text_rank, perms_flags, accepted_at, changed_at, banned, info) VALUES(?1,?2,?3,?4,?5,0,?6) ON CONFLICT(pubkey) DO UPDATE SET banned=0, perms_flags=excluded.perms_flags", users_tbl),
                turso::params![cc_pub.as_slice(), "", user_perms, now, 0i64, empty_info],
            ).await {
                error!("Failed to add user to chat {}: {}", chat_id, e);
                let _ = cc.write_err(req_id, "db error").await;
                return;
            }
        }

        // System message: user added
        let mut body = vec![0u8; 1 + 32 + 32 + 32];
        body[0] = SYS_USER_ADDED;
        body[1..33].copy_from_slice(&cc_pub);
        body[33..65].copy_from_slice(&from_pubkey);
        body[65..97].copy_from_slice(&rand32());

        let now = now_unix();
        if let Err(e) = broadcast_system_message(state, &cc.db_conn, chat_id, &body, None, now, true).await {
            error!("{}", e);
            let _ = cc.write_err(req_id, "db error").await;
            return;
        }

        {
            let _guard = state.db.write_mu.lock().await;
            let _ = cc.db_conn.execute("DELETE FROM invites WHERE id=?1", turso::params![invite_id]).await;
        }
    } else {
        // Rejected
        let _guard = state.db.write_mu.lock().await;
        let _ = cc.db_conn.execute("DELETE FROM invites WHERE id=?1", turso::params![invite_id]).await;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

// ---- Member info handlers ----

async fn handle_update_member_info(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let timestamp = match tlv_get_u64(&tlvs, TAG_TIMESTAMP) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid timestamp").await; return; }
    };
    let encrypted_blob = tlv_get_bytes_optional(&tlvs, TAG_MEMBER_INFO).unwrap_or(&[]).to_vec();

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((_, false)) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let users_tbl = format!("users-{}", chat_id);
    {
        let _guard = state.db.write_mu.lock().await;
        if let Err(e) = cc.db_conn.execute(
            &format!("UPDATE \"{}\" SET info=?1, changed_at=?2 WHERE pubkey=?3", users_tbl),
            turso::params![encrypted_blob.as_slice(), timestamp as i64, cc_pub.as_slice()],
        ).await {
            error!("Failed to update member info: {}", e);
            let _ = cc.write_err(req_id, "db error").await;
            return;
        }
    }

    // Broadcast member info update
    let broadcast_payload = build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_CHAT_ID, chat_id)?;
        tlv_encode_u32(w, TAG_COUNT, 1)?;
        tlv_encode_bytes(w, TAG_USER_PUBKEY, &cc_pub)?;
        tlv_encode_bytes(w, TAG_MEMBER_INFO, &encrypted_blob)?;
        tlv_encode_u64(w, TAG_TIMESTAMP, timestamp)
    }).unwrap_or_default();

    state.broadcast_to_chat(chat_id, None, CMD_GOT_MEMBER_INFO as u16, broadcast_payload).await;

    let _ = cc.write_ok(req_id, &[]).await;
}

async fn handle_get_members_info(_state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };
    let since_ts = tlv_get_u64(&tlvs, TAG_LAST_UPDATE).unwrap_or(0);

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((_, false)) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let users_tbl = format!("users-{}", chat_id);
    let q = format!("SELECT pubkey, info, changed_at FROM \"{}\" WHERE banned = 0", users_tbl);
    let mut rows = match cc.db_conn.query(&q, ()).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to query members info for chat {}: {}", chat_id, e);
            let _ = cc.write_err(req_id, "db error").await;
            return;
        }
    };

    struct MemberInfo {
        pubkey: Vec<u8>,
        info: Option<Vec<u8>>,
        timestamp: i64,
    }
    let mut members = Vec::new();

    while let Ok(Some(row)) = rows.next().await {
        let pubkey: Vec<u8> = row.get(0).unwrap_or_default();
        let info_bytes: Option<Vec<u8>> = row.get(1).ok();
        let changed_at: i64 = row.get(2).unwrap_or(0);

        let info = if let Some(ref ib) = info_bytes {
            if !ib.is_empty() && (since_ts == 0 || changed_at as u64 > since_ts) {
                Some(ib.clone())
            } else {
                None
            }
        } else {
            None
        };

        members.push(MemberInfo { pubkey, info, timestamp: changed_at });
    }

    let resp = build_tlv_payload(|w| {
        tlv_encode_u32(w, TAG_COUNT, members.len() as u32)?;
        for m in &members {
            tlv_encode_bytes(w, TAG_USER_PUBKEY, &m.pubkey)?;
            tlv_encode_bytes(w, TAG_MEMBER_INFO, m.info.as_deref().unwrap_or(&[]))?;
            tlv_encode_u64(w, TAG_TIMESTAMP, m.timestamp as u64)?;
        }
        Ok(())
    }).unwrap_or_default();

    let _ = cc.write_ok(req_id, &resp).await;
}

async fn handle_get_members(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "auth required").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let chat_id = match tlv_get_i64(&tlvs, TAG_CHAT_ID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid chat id").await; return; }
    };

    let cc_pub = *cc.pub_key.read().await;
    match lookup_perms(&cc.db_conn,chat_id, &cc_pub).await {
        Some((_, false)) => {}
        _ => { let _ = cc.write_err(req_id, "not a member or banned").await; return; }
    }

    let users_tbl = format!("users-{}", chat_id);
    let q = format!("SELECT pubkey, perms_flags, last_seen FROM \"{}\" WHERE banned=0", users_tbl);
    let mut rows = match cc.db_conn.query(&q, ()).await {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "db error").await; return; }
    };

    struct Member {
        pubkey: [u8; 32],
        perms: u8,
        online: u8,
        last_seen: i64,
    }
    let mut members = Vec::new();

    while let Ok(Some(row)) = rows.next().await {
        let pk: Vec<u8> = row.get(0).unwrap_or_default();
        let perms: i64 = row.get(1).unwrap_or(0);
        let last_seen: i64 = row.get(2).unwrap_or(0);

        if pk.len() != 32 { continue; }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pk);

        // Check online status
        let mut online: u8 = 0;
        let client_ids: Vec<ClientId> = {
            let auth = state.auth_clients.read().await;
            auth.get(&pubkey).map(|s| s.iter().copied().collect()).unwrap_or_default()
        };

        if !client_ids.is_empty() {
            let subs = state.chat_subs.read().await;
            if let Some(chat_subs) = subs.get(&chat_id) {
                for cid in &client_ids {
                    if chat_subs.contains(cid) {
                        online = 1;
                        break;
                    }
                }
            }
        }

        members.push(Member { pubkey, perms: perms as u8, online, last_seen });
    }

    let resp = build_tlv_payload(|w| {
        tlv_encode_u32(w, TAG_COUNT, members.len() as u32)?;
        for m in &members {
            tlv_encode_bytes(w, TAG_USER_PUBKEY, &m.pubkey)?;
            tlv_encode_u8(w, TAG_PERMS, m.perms)?;
            tlv_encode_u8(w, TAG_ONLINE, m.online)?;
            tlv_encode_u64(w, TAG_LAST_SEEN, m.last_seen as u64)?;
        }
        Ok(())
    }).unwrap_or_default();

    let _ = cc.write_ok(req_id, &resp).await;
}

// ---- Broadcasting helpers ----

/// Broadcast a system message, optionally storing in DB.
pub async fn broadcast_system_message(
    state: &Arc<ServerState>,
    conn: &turso::Connection,
    chat_id: i64,
    body: &[u8],
    sender_id: Option<ClientId>,
    timestamp: i64,
    store_in_db: bool,
) -> Result<(), String> {
    let guid = generate_message_guid(timestamp, body);
    let mut msg_id: i64 = 0;

    if store_in_db {
        let msg_tbl = format!("messages-{}", chat_id);
        let _guard = state.db.write_mu.lock().await;
        if let Err(e) = conn.execute(
            &format!("INSERT INTO \"{}\"(ts, guid, author) VALUES(?1,?2,?3)", msg_tbl),
            turso::params![timestamp, guid, state.mediator_pub.as_slice()],
        ).await {
            return Err(format!("failed to insert system message: {}", e));
        }
        // Get last insert id
        if let Ok(mut r) = conn.query(
            &format!("SELECT id FROM \"{}\" WHERE guid=?1", msg_tbl),
            turso::params![guid],
        ).await {
            if let Ok(Some(row)) = r.next().await {
                msg_id = row.get(0).unwrap_or(0);
            }
        }

        // Store in cache
        let key = format!("{:016x}:{:016x}", chat_id, guid);
        state.cache.set(&key, body).await;
    }

    let broadcast_payload = build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_CHAT_ID, chat_id)?;
        tlv_encode_i64(w, TAG_MESSAGE_ID, msg_id)?;
        tlv_encode_i64(w, TAG_MESSAGE_GUID, guid)?;
        tlv_encode_i64(w, TAG_TIMESTAMP, timestamp)?;
        tlv_encode_bytes(w, TAG_PUBKEY, &state.mediator_pub)?;
        tlv_encode_bytes(w, TAG_MESSAGE_BLOB, body)
    }).map_err(|e| format!("failed to encode system message broadcast: {}", e))?;

    if sender_id.is_some() {
        state.broadcast_message(chat_id, sender_id, broadcast_payload).await;
    } else {
        state.broadcast_to_chat(chat_id, None, CMD_GOT_MESSAGE as u16, broadcast_payload).await;
    }

    Ok(())
}

/// Broadcast member online status change.
pub async fn broadcast_member_online_status(state: &Arc<ServerState>, chat_id: i64, member_pubkey: [u8; 32], is_online: bool, timestamp: i64) {
    let online: u8 = if is_online { 1 } else { 0 };

    let mut body = vec![0u8; 42];
    body[0] = SYS_MEMBER_ONLINE;
    body[1..33].copy_from_slice(&member_pubkey);
    body[33] = online;
    body[34..42].copy_from_slice(&(timestamp as u64).to_be_bytes());

    let guid = generate_message_guid(timestamp, &body);

    let broadcast_payload = match build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_CHAT_ID, chat_id)?;
        tlv_encode_i64(w, TAG_MESSAGE_ID, 0)?;
        tlv_encode_i64(w, TAG_MESSAGE_GUID, guid)?;
        tlv_encode_i64(w, TAG_TIMESTAMP, timestamp)?;
        tlv_encode_bytes(w, TAG_PUBKEY, &state.mediator_pub)?;
        tlv_encode_bytes(w, TAG_MESSAGE_BLOB, &body)
    }) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to encode member online status broadcast: {}", e);
            return;
        }
    };

    state.broadcast_to_chat(chat_id, None, CMD_GOT_MESSAGE as u16, broadcast_payload).await;
}

// ---- Invite helpers ----

async fn send_invite_to_client(state: &Arc<ServerState>, cc: &Arc<ClientConn>, conn: &turso::Connection, invite_id: i64, timestamp: i64, from_pubkey: &[u8], chat_id: i64, encrypted_data: &[u8]) -> bool {
    // Get chat metadata
    let sett_tbl = format!("settings-{}", chat_id);
    let q = format!("SELECT name, description, avatar FROM \"{}\"", sett_tbl);
    let (chat_name, chat_desc, chat_avatar): (String, String, Option<Vec<u8>>) = match conn.query(&q, ()).await {
        Ok(mut r) => match r.next().await {
            Ok(Some(row)) => (
                row.get(0).unwrap_or_default(),
                row.get(1).unwrap_or_default(),
                row.get(2).ok(),
            ),
            _ => { warn!("Failed to get chat metadata for {}", chat_id); return false; }
        },
        Err(_) => { warn!("Failed to get chat metadata for {}", chat_id); return false; }
    };

    let payload = match build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_INVITE_ID, invite_id)?;
        tlv_encode_i64(w, TAG_CHAT_ID, chat_id)?;
        tlv_encode_bytes(w, TAG_PUBKEY, from_pubkey)?;
        tlv_encode_u64(w, TAG_TIMESTAMP, timestamp as u64)?;
        tlv_encode_string(w, TAG_CHAT_NAME, &chat_name)?;
        tlv_encode_string(w, TAG_CHAT_DESC, &chat_desc)?;
        if let Some(ref av) = chat_avatar {
            tlv_encode_bytes(w, TAG_CHAT_AVATAR, av)?;
        }
        tlv_encode_bytes(w, TAG_INVITE_DATA, encrypted_data)
    }) {
        Ok(p) => p,
        Err(e) => { warn!("Failed to encode invite notification: {}", e); return false; }
    };

    if cc.write_push(CMD_GOT_INVITE as u16, &payload).await.is_err() {
        return false;
    }

    // Mark as sent
    let _guard = state.db.write_mu.lock().await;
    let _ = conn.execute("UPDATE invites SET sent=1 WHERE id=?1", turso::params![invite_id]).await;

    true
}

async fn send_pending_invites(state: &Arc<ServerState>, cc: &Arc<ClientConn>, conn: &turso::Connection) {
    let cc_pub = *cc.pub_key.read().await;
    let q = "SELECT id, timestamp, from_pubkey, chat_id, encrypted_data FROM invites WHERE to_pubkey=?1 AND sent=0";
    let mut rows = match conn.query(q, turso::params![cc_pub.as_slice()]).await {
        Ok(r) => r,
        Err(e) => { warn!("Failed to query pending invites: {}", e); return; }
    };

    struct Invite {
        id: i64,
        timestamp: i64,
        from_pubkey: Vec<u8>,
        chat_id: i64,
        encrypted_data: Vec<u8>,
    }
    let mut invites = Vec::new();
    while let Ok(Some(row)) = rows.next().await {
        invites.push(Invite {
            id: row.get(0).unwrap_or(0),
            timestamp: row.get(1).unwrap_or(0),
            from_pubkey: row.get(2).unwrap_or_default(),
            chat_id: row.get(3).unwrap_or(0),
            encrypted_data: row.get(4).unwrap_or_default(),
        });
    }

    if invites.is_empty() { return; }

    info!("Sending {} pending invite(s) to {}", invites.len(), hex::encode(&cc_pub[..4]));
    for inv in &invites {
        send_invite_to_client(state, cc, conn, inv.id, inv.timestamp, &inv.from_pubkey, inv.chat_id, &inv.encrypted_data).await;
    }
}

async fn request_member_info(cc: &Arc<ClientConn>, conn: &turso::Connection, chat_id: i64) {
    let cc_pub = *cc.pub_key.read().await;
    let users_tbl = format!("users-{}", chat_id);
    let q = format!("SELECT IFNULL(changed_at, 0) FROM \"{}\" WHERE pubkey=?1", users_tbl);
    let last_update: i64 = match conn.query(&q, turso::params![cc_pub.as_slice()]).await {
        Ok(mut r) => match r.next().await {
            Ok(Some(row)) => row.get(0).unwrap_or(0),
            _ => 0,
        },
        Err(_) => 0,
    };

    let payload = match build_tlv_payload(|w| {
        tlv_encode_i64(w, TAG_CHAT_ID, chat_id)?;
        tlv_encode_u64(w, TAG_LAST_UPDATE, last_update as u64)
    }) {
        Ok(p) => p,
        Err(e) => { warn!("Failed to encode member info request: {}", e); return; }
    };

    let _ = cc.write_push(CMD_REQUEST_MEMBER_INFO as u16, &payload).await;
}

// ---- Invite cleanup ----

pub async fn invite_cleanup_worker(state: Arc<ServerState>) {
    cleanup_old_invites(&state).await;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        interval.tick().await;
        cleanup_old_invites(&state).await;
    }
}

async fn cleanup_old_invites(state: &Arc<ServerState>) {
    const THREE_DAYS: i64 = 3 * 24 * 3600;
    let cutoff = now_unix() - THREE_DAYS;

    let conn = match state.db.connect() {
        Ok(c) => c,
        Err(e) => { warn!("cleanup_old_invites: failed to connect: {}", e); return; }
    };

    let _guard = state.db.write_mu.lock().await;
    match conn.execute("DELETE FROM invites WHERE timestamp < ?1", turso::params![cutoff]).await {
        Ok(_) => {}
        Err(e) => warn!("Failed to clean up old invites: {}", e),
    }
}
