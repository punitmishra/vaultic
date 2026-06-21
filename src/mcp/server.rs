//! MCP server implementation for Vaultic.
//!
//! Implements the Model Context Protocol server that exposes vault operations
//! as tools callable by AI assistants like Claude Code.

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParam, CallToolResult, Content, Implementation, ListToolsResult,
    PaginatedRequestParam, ServerCapabilities, ServerInfo, Tool, ToolsCapability,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::Error as RmcpError;
use serde_json::json;
use uuid::Uuid;

use crate::agent::paths::agent_socket_path;
use crate::agent::protocol::ErrorCode;
use crate::agent::{AgentClient, ClientError};
use crate::mcp::error::McpError;
use crate::mcp::tools::{
    CredentialResult, EntryInfo, GetCredentialParams, GetPasswordParams, GetTotpParams,
    ListEntriesParams, SearchEntriesParams, ToolContext, TotpResult, VaultStatusResult,
};
use crate::models::SearchFilter;

/// The Vaultic MCP server.
///
/// Connects to the vaultic-agent daemon and exposes vault operations as MCP tools.
#[derive(Clone)]
pub struct VaulticMcpServer {
    /// Tool execution context (consent handler, rate limiter).
    context: Arc<ToolContext>,
    /// Custom socket path (if provided).
    socket_path: Option<String>,
}

impl VaulticMcpServer {
    /// Create a new MCP server.
    pub fn new(require_consent: bool) -> Self {
        Self {
            context: Arc::new(ToolContext::new(require_consent)),
            socket_path: None,
        }
    }

    /// Create a new MCP server with a custom socket path.
    pub fn with_socket_path(require_consent: bool, socket_path: String) -> Self {
        Self {
            context: Arc::new(ToolContext::new(require_consent)),
            socket_path: Some(socket_path),
        }
    }

    /// Get or establish connection to vaultic-agent.
    async fn get_client(&self) -> Result<AgentClient, McpError> {
        let socket = match &self.socket_path {
            Some(p) => std::path::PathBuf::from(p),
            None => agent_socket_path().map_err(|e| {
                McpError::InvalidParams(format!("Cannot determine agent socket path: {}", e))
            })?,
        };

        if !socket.exists() {
            return Err(McpError::AgentNotRunning);
        }

        AgentClient::connect(&socket).await.map_err(|e| match e {
            ClientError::Transport(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
                McpError::AgentNotRunning
            }
            _ => McpError::Agent(e),
        })
    }

    /// Execute vault_status tool.
    async fn vault_status(&self) -> Result<VaultStatusResult, McpError> {
        let mut client = self.get_client().await?;
        let status = client.status().await?;

        Ok(VaultStatusResult {
            locked: !status.unlocked,
            vault_path: status.vault_path,
            entry_count: status.entry_count,
            expires_at: status.expires_at.map(|t| t.to_rfc3339()),
        })
    }

    /// Execute list_entries tool.
    async fn list_entries(&self, params: ListEntriesParams) -> Result<Vec<EntryInfo>, McpError> {
        let mut client = self.get_client().await?;

        let entries = if params.query.is_some() || params.folder.is_some() || params.tags.is_some()
        {
            let filter = SearchFilter {
                query: params.query,
                folder: params.folder,
                tags: params.tags.unwrap_or_default(),
                ..Default::default()
            };
            client.list_filtered(filter).await?
        } else {
            client.list_summary().await?
        };

        Ok(entries.into_iter().map(EntryInfo::from).collect())
    }

    /// Execute search_entries tool.
    async fn search_entries(
        &self,
        params: SearchEntriesParams,
    ) -> Result<Vec<EntryInfo>, McpError> {
        let mut client = self.get_client().await?;
        let entries = client.search(params.query).await?;
        Ok(entries.into_iter().map(EntryInfo::from).collect())
    }

    /// Find entry by ID or name.
    async fn resolve_entry(
        &self,
        client: &mut AgentClient,
        entry_id: Option<String>,
        name: Option<String>,
    ) -> Result<Uuid, McpError> {
        if let Some(id_str) = entry_id {
            Uuid::parse_str(&id_str)
                .map_err(|_| McpError::InvalidParams(format!("Invalid UUID: {}", id_str)))
        } else if let Some(name) = name {
            let entries = client.search(name.clone()).await?;
            entries
                .first()
                .map(|e| e.id)
                .ok_or(McpError::NotFound(name))
        } else {
            Err(McpError::InvalidParams(
                "Either entry_id or name must be provided".to_string(),
            ))
        }
    }

    /// Execute get_password tool.
    async fn get_password(&self, params: GetPasswordParams) -> Result<String, McpError> {
        self.context.check_rate_limit().await?;

        let mut client = self.get_client().await?;
        let id = self
            .resolve_entry(&mut client, params.entry_id, params.name.clone())
            .await?;

        // Get entry name for consent prompt
        let entries = client.list_summary().await?;
        let entry_name = entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.name.clone())
            .unwrap_or_else(|| params.name.unwrap_or_else(|| id.to_string()));

        self.context.request_consent("get_password", &entry_name)?;

        let entry = client.get_entry(id).await.map_err(|e| {
            if e.agent_code() == Some(ErrorCode::NotFound) {
                McpError::NotFound(entry_name.clone())
            } else {
                McpError::Agent(e)
            }
        })?;

        entry
            .password
            .map(|p| p.expose().to_string())
            .ok_or_else(|| McpError::NotFound(format!("{} has no password", entry_name)))
    }

    /// Execute get_credential tool.
    async fn get_credential(
        &self,
        params: GetCredentialParams,
    ) -> Result<CredentialResult, McpError> {
        self.context.check_rate_limit().await?;

        let mut client = self.get_client().await?;
        let id = self
            .resolve_entry(&mut client, params.entry_id, params.name.clone())
            .await?;

        // Get entry name for consent prompt
        let entries = client.list_summary().await?;
        let entry_name = entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.name.clone())
            .unwrap_or_else(|| params.name.unwrap_or_else(|| id.to_string()));

        self.context
            .request_consent("get_credential", &entry_name)?;

        let entry = client.get_entry(id).await.map_err(|e| {
            if e.agent_code() == Some(ErrorCode::NotFound) {
                McpError::NotFound(entry_name.clone())
            } else {
                McpError::Agent(e)
            }
        })?;

        let password = entry
            .password
            .map(|p| p.expose().to_string())
            .ok_or_else(|| McpError::NotFound(format!("{} has no password", entry_name)))?;

        Ok(CredentialResult {
            username: entry.username,
            password,
            url: entry.url,
        })
    }

    /// Execute get_totp tool.
    async fn get_totp(&self, params: GetTotpParams) -> Result<TotpResult, McpError> {
        self.context.check_rate_limit().await?;

        let mut client = self.get_client().await?;
        let id = self
            .resolve_entry(&mut client, params.entry_id, params.name.clone())
            .await?;

        // Get entry name for consent prompt
        let entries = client.list_summary().await?;
        let entry_name = entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.name.clone())
            .unwrap_or_else(|| params.name.unwrap_or_else(|| id.to_string()));

        self.context.request_consent("get_totp", &entry_name)?;

        let totp = client.get_totp(id).await.map_err(|e| {
            if e.agent_code() == Some(ErrorCode::NotFound) {
                McpError::NotFound(format!("{} has no TOTP configured", entry_name))
            } else {
                McpError::Agent(e)
            }
        })?;

        Ok(TotpResult {
            code: totp.code,
            remaining_seconds: totp.period_remaining_seconds,
        })
    }

    /// Build the list of available tools.
    fn build_tools() -> Vec<Tool> {
        vec![
            Tool::new(
                "vault_status",
                "Check if the Vaultic vault is locked or unlocked. Returns vault status including lock state, vault path, entry count, and session expiry time.",
                Arc::new(json!({
                    "type": "object",
                    "properties": {}
                }).as_object().unwrap().clone()),
            ),
            Tool::new(
                "list_entries",
                "List all entries in the vault without revealing secrets. Can filter by query, folder, or tags. Use this to find entry IDs before retrieving passwords.",
                Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Optional search query to filter entries"
                        },
                        "folder": {
                            "type": "string",
                            "description": "Filter by folder name"
                        },
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by tags (entries must have all specified tags)"
                        }
                    }
                }).as_object().unwrap().clone()),
            ),
            Tool::new(
                "search_entries",
                "Fuzzy search entries by name, username, URL, or tags. Returns matching entries without secrets.",
                Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (fuzzy matches name, username, URL, tags)"
                        }
                    },
                    "required": ["query"]
                }).as_object().unwrap().clone()),
            ),
            Tool::new(
                "get_password",
                "Get the password for an entry. REQUIRES USER CONSENT - the user will be prompted to approve access. Use entry_id from list_entries for exact match, or name for fuzzy match.",
                Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "entry_id": {
                            "type": "string",
                            "description": "Entry UUID from list_entries (preferred)"
                        },
                        "name": {
                            "type": "string",
                            "description": "Entry name for fuzzy matching"
                        }
                    }
                }).as_object().unwrap().clone()),
            ),
            Tool::new(
                "get_credential",
                "Get full credential (username + password + URL) for an entry. REQUIRES USER CONSENT - the user will be prompted to approve access.",
                Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "entry_id": {
                            "type": "string",
                            "description": "Entry UUID from list_entries (preferred)"
                        },
                        "name": {
                            "type": "string",
                            "description": "Entry name for fuzzy matching"
                        }
                    }
                }).as_object().unwrap().clone()),
            ),
            Tool::new(
                "get_totp",
                "Get the current TOTP code for an entry. REQUIRES USER CONSENT. Returns the 6-digit code and seconds remaining until it changes.",
                Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "entry_id": {
                            "type": "string",
                            "description": "Entry UUID from list_entries (preferred)"
                        },
                        "name": {
                            "type": "string",
                            "description": "Entry name for fuzzy matching"
                        }
                    }
                }).as_object().unwrap().clone()),
            ),
        ]
    }
}

impl ServerHandler for VaulticMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: None }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "vaultic-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "Vaultic is a local-first password manager. Use vault_status to check if the vault is unlocked. Use list_entries or search_entries to find credentials, then get_password, get_credential, or get_totp to retrieve secrets. Secret access requires user consent.".to_string()
            ),
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, RmcpError>> + Send + '_ {
        async move {
            Ok(ListToolsResult {
                tools: Self::build_tools(),
                next_cursor: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, RmcpError>> + Send + '_ {
        let name = request.name.to_string();
        let args = request
            .arguments
            .map(serde_json::Value::Object)
            .unwrap_or(json!({}));

        async move {
            let result: Result<serde_json::Value, String> = match name.as_str() {
                "vault_status" => self
                    .vault_status()
                    .await
                    .map(|r| serde_json::to_value(r).unwrap())
                    .map_err(|e| e.to_ai_message()),

                "list_entries" => {
                    let params: ListEntriesParams =
                        serde_json::from_value(args).unwrap_or(ListEntriesParams {
                            query: None,
                            folder: None,
                            tags: None,
                        });
                    self.list_entries(params)
                        .await
                        .map(|r| serde_json::to_value(r).unwrap())
                        .map_err(|e| e.to_ai_message())
                }

                "search_entries" => {
                    let params: SearchEntriesParams = match serde_json::from_value(args) {
                        Ok(p) => p,
                        Err(e) => return Ok(CallToolResult::error(vec![Content::text(
                            format!("Invalid parameters: {}", e)
                        )])),
                    };
                    self.search_entries(params)
                        .await
                        .map(|r| serde_json::to_value(r).unwrap())
                        .map_err(|e| e.to_ai_message())
                }

                "get_password" => {
                    let params: GetPasswordParams =
                        serde_json::from_value(args).unwrap_or(GetPasswordParams {
                            entry_id: None,
                            name: None,
                        });
                    self.get_password(params)
                        .await
                        .map(|r| json!({"password": r}))
                        .map_err(|e| e.to_ai_message())
                }

                "get_credential" => {
                    let params: GetCredentialParams =
                        serde_json::from_value(args).unwrap_or(GetCredentialParams {
                            entry_id: None,
                            name: None,
                        });
                    self.get_credential(params)
                        .await
                        .map(|r| serde_json::to_value(r).unwrap())
                        .map_err(|e| e.to_ai_message())
                }

                "get_totp" => {
                    let params: GetTotpParams =
                        serde_json::from_value(args).unwrap_or(GetTotpParams {
                            entry_id: None,
                            name: None,
                        });
                    self.get_totp(params)
                        .await
                        .map(|r| serde_json::to_value(r).unwrap())
                        .map_err(|e| e.to_ai_message())
                }

                _ => Err(format!("Unknown tool: {}", name)),
            };

            match result {
                Ok(value) => {
                    let text = serde_json::to_string_pretty(&value)
                        .unwrap_or_else(|_| value.to_string());
                    Ok(CallToolResult::success(vec![Content::text(text)]))
                }
                Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_info() {
        let server = VaulticMcpServer::new(false);
        let info = server.get_info();
        assert_eq!(info.server_info.name, "vaultic-mcp");
    }

    #[test]
    fn test_tools_defined() {
        let tools = VaulticMcpServer::build_tools();
        assert_eq!(tools.len(), 6);
        assert!(tools.iter().any(|t| t.name == "vault_status"));
        assert!(tools.iter().any(|t| t.name == "list_entries"));
        assert!(tools.iter().any(|t| t.name == "search_entries"));
        assert!(tools.iter().any(|t| t.name == "get_password"));
        assert!(tools.iter().any(|t| t.name == "get_credential"));
        assert!(tools.iter().any(|t| t.name == "get_totp"));
    }
}
