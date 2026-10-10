/// The authenticated principal attached to a request.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// User id.
    pub user_id: i64,
    /// Login name.
    pub username: String,
    /// Whether the user is an administrator.
    pub is_admin: bool,
    /// Hash of the session token, when the request was authenticated
    /// with a session (bearer token or cookie) rather than Basic auth.
    pub session_hash: Option<[u8; 32]>,
}
