//! Add PR comment safe output tool

use log::{debug, info};
use percent_encoding::utf8_percent_encode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::PATH_SEGMENT;
use crate::safeoutputs::{ExecutionContext, ExecutionResult, Executor, Validate};
use crate::sanitize::{SanitizeContent, sanitize as sanitize_text, sanitize_config};
use crate::tool_result;
use crate::validate::reject_pipeline_injection;
use ado_aw_derive::SanitizeConfig;
use anyhow::{Context, ensure};

/// Parameters for adding a comment thread on a pull request
#[derive(Deserialize, JsonSchema)]
pub struct AddPrCommentParams {
    /// The pull request ID to comment on
    pub pull_request_id: i32,

    /// Comment text in markdown format. Ensure adequate content > 10 characters.
    ///
    /// For an inline comment (with `file_path` + `line`), include a fenced
    /// ```` ```suggestion ```` block holding the **whole corrected line(s)** to
    /// render a one-click "Apply suggestion". The framework anchors the thread to
    /// the entire target line range, so the applied change replaces the line(s)
    /// cleanly — write the suggestion body byte-for-byte (literal `<`, `>`, `&`,
    /// `"`; never HTML entities) with the original indentation, and no trailing
    /// newline inside the fence.
    pub content: String,

    /// Repository alias: "self" for pipeline repo, or an alias from the checkout list.
    /// Defaults to "self" if omitted.
    #[serde(default = "default_repository")]
    pub repository: String,

    /// File path for an inline comment. When set, the comment is anchored to this file.
    /// A `suggestion` block in `content` becomes an applyable single-line change.
    #[serde(default)]
    pub file_path: Option<String>,

    /// Starting line number for a multi-line inline comment. Requires `file_path` and `line`.
    /// When set, the comment spans from `start_line` to `line`. Must be strictly less than
    /// `line` (use `line` alone for single-line comments — do not pass `start_line == line`).
    /// A `suggestion` block in `content` then applies across the whole `start_line..line` range.
    #[serde(default)]
    pub start_line: Option<i32>,

    /// Line number for an inline comment. Requires `file_path` to be set.
    #[serde(default)]
    pub line: Option<i32>,

    /// Thread status: "active" (default), "fixed", "wont-fix", "closed", or "by-design".
    /// CamelCase forms ("Active", "WontFix", etc.) are also accepted for backwards compatibility.
    #[serde(default = "default_status")]
    pub status: String,
}

fn default_repository() -> String {
    "self".to_string()
}

fn default_status() -> String {
    "active".to_string()
}

impl Validate for AddPrCommentParams {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.pull_request_id > 0, "pull_request_id must be positive");
        ensure!(
            self.content.len() >= 10,
            "content must be at least 10 characters"
        );
        ensure!(
            status_to_int(&self.status).is_some(),
            "status must be one of: {}",
            VALID_STATUSES.join(", ")
        );
        if self.line.is_some() {
            ensure!(
                self.file_path.is_some(),
                "line requires file_path to be set"
            );
        }
        if self.start_line.is_some() {
            ensure!(self.line.is_some(), "start_line requires line to be set");
            if let (Some(start), Some(end)) = (self.start_line, self.line) {
                ensure!(
                    start < end,
                    "start_line ({}) must be less than line ({})",
                    start,
                    end
                );
            }
        }
        if let Some(fp) = &self.file_path {
            validate_file_path(fp)?;
        }
        reject_pipeline_injection(&self.repository, "repository")?;
        Ok(())
    }
}

tool_result! {
    name = "add-pr-comment",
    write = true,
    params = AddPrCommentParams,
    /// Result of adding a comment thread on a pull request
    pub struct AddPrCommentResult {
        pull_request_id: i32,
        content: String,
        repository: String,
        file_path: Option<String>,
        start_line: Option<i32>,
        line: Option<i32>,
        status: String,
    }
}

impl SanitizeContent for AddPrCommentResult {
    fn sanitize_content_fields(&mut self) {
        self.content = sanitize_text(&self.content);
        self.repository = sanitize_config(&self.repository);
        // Strip control characters from remaining structural fields for defense-in-depth
        self.status = self.status.chars().filter(|c| !c.is_control()).collect();
        self.file_path = self
            .file_path
            .as_ref()
            .map(|fp| fp.chars().filter(|c| !c.is_control()).collect());
    }
}

/// Configuration for the add-pr-comment tool (specified in front matter)
///
/// Example front matter:
/// ```yaml
/// safe-outputs:
///   add-pr-comment:
///     comment-prefix: "[Agent Review] "
///     allowed-repositories:
///       - self
///       - other-repo
///     allowed-statuses:
///       - Active
///       - Closed
/// ```
#[derive(Debug, Clone, SanitizeConfig, Serialize, Deserialize)]
pub struct AddPrCommentConfig {
    /// Prefix prepended to all comments (e.g., "[Agent Review] ")
    #[serde(default, rename = "comment-prefix")]
    pub comment_prefix: Option<String>,

    /// Restrict which repositories the agent can comment on.
    /// If empty, all repositories in the checkout list (plus "self") are allowed.
    #[serde(default, rename = "allowed-repositories")]
    pub allowed_repositories: Vec<String>,

    /// Restrict which thread statuses can be set.
    /// If empty, all valid statuses are allowed.
    #[serde(default, rename = "allowed-statuses")]
    pub allowed_statuses: Vec<String>,
    /// Whether to include agent execution stats in the output (default: true).
    #[serde(
        default = "crate::agent_stats::default_include_stats",
        rename = "include-stats"
    )]
    pub include_stats: bool,
}

impl Default for AddPrCommentConfig {
    fn default() -> Self {
        Self {
            comment_prefix: None,
            allowed_repositories: Vec::new(),
            allowed_statuses: Vec::new(),
            include_stats: true,
        }
    }
}

/// Map a thread status string to the ADO API integer value.
/// Accepts both kebab-case (preferred) and CamelCase for backwards compatibility.
fn status_to_int(status: &str) -> Option<i32> {
    match status {
        "active" | "Active" => Some(1),
        "fixed" | "Fixed" => Some(2),
        "wont-fix" | "WontFix" => Some(3),
        "closed" | "Closed" => Some(4),
        "by-design" | "ByDesign" => Some(5),
        _ => None,
    }
}

/// All valid thread status strings (kebab-case canonical form)
const VALID_STATUSES: &[&str] = &["active", "fixed", "wont-fix", "closed", "by-design"];

/// Validate a file path for inline comments: no `..` path traversal, not absolute
fn validate_file_path(path: &str) -> anyhow::Result<()> {
    ensure!(!path.is_empty(), "file_path must not be empty");
    ensure!(
        !path.split(['/', '\\']).any(|component| component == ".."),
        "file_path must not contain a '..' path component"
    );
    ensure!(
        !path.starts_with('/') && !path.starts_with('\\'),
        "file_path must not be absolute"
    );
    Ok(())
}

/// Compute the ADO right-side end offset that makes an inline thread cover the
/// **entire** target line: `(UTF-16 length of the line's text) + 1`.
///
/// When a `suggestion` is applied, ADO replaces the half-open range
/// `[rightFileStart, rightFileEnd)`. Anchoring the end at the start of the same
/// line (offset 1) is a zero-width range, so ADO *inserts* the suggestion and
/// leaves the original line in place (a duplicated line); anchoring at the start
/// of the *next* line swallows the trailing newline and joins the following line
/// onto the suggestion. Measuring the line text and pointing one past its last
/// character makes "Apply suggestion" a clean, full-line replacement.
///
/// Offsets are 1-based and counted in UTF-16 code units, matching ADO's editor
/// model. Returns `None` when the file or line cannot be read, in which case the
/// caller falls back to the legacy end offset of 1 (acceptable for a plain inline
/// comment, whose anchor does not need to span an exact range).
fn line_end_offset(
    source_directory: &std::path::Path,
    file_path: &str,
    line: i32,
) -> Option<usize> {
    if line < 1 {
        return None;
    }
    let contents = std::fs::read_to_string(source_directory.join(file_path)).ok()?;
    // `str::lines()` strips the trailing `\n`/`\r\n`; guard against a lone `\r`.
    let text = contents.lines().nth((line - 1) as usize)?;
    let text = text.strip_suffix('\r').unwrap_or(text);
    Some(text.encode_utf16().count() + 1)
}

/// Build the ADO `threadContext` for an inline comment anchored to a file.
///
/// The right-side range spans from the **start of `start_line`** to **`end_offset`
/// on `end_line`** (`start_line == end_line` for a single line). With `end_offset`
/// set to the last line's `(UTF-16 length) + 1` by [`line_end_offset`], applying a
/// `suggestion` replaces the whole `start_line..=end_line` block cleanly — single
/// and multi-line suggestions use the same shape.
fn inline_thread_context(
    file_path: &str,
    start_line: i32,
    end_line: i32,
    end_offset: usize,
) -> serde_json::Value {
    serde_json::json!({
        "filePath": format!("/{}", file_path),
        "rightFileStart": { "line": start_line, "offset": 1 },
        "rightFileEnd": { "line": end_line, "offset": end_offset }
    })
}

#[async_trait::async_trait]
impl Executor for AddPrCommentResult {
    fn dry_run_summary(&self) -> String {
        format!("add comment to PR #{}", self.pull_request_id)
    }

    async fn execute_impl(&self, ctx: &ExecutionContext) -> anyhow::Result<ExecutionResult> {
        info!(
            "Adding comment to PR #{}: {} chars",
            self.pull_request_id,
            self.content.len()
        );
        debug!(
            "add-pr-comment: pr_id={}, content length={}",
            self.pull_request_id,
            self.content.len()
        );

        let org_url = ctx
            .ado_org_url
            .as_ref()
            .context("AZURE_DEVOPS_ORG_URL not set")?;
        let project = ctx
            .ado_project
            .as_ref()
            .context("SYSTEM_TEAMPROJECT not set")?;
        let token = ctx
            .access_token
            .as_ref()
            .context("No access token available (SYSTEM_ACCESSTOKEN or AZURE_DEVOPS_EXT_PAT)")?;
        debug!("ADO org: {}, project: {}", org_url, project);

        let config: AddPrCommentConfig = ctx.get_tool_config("add-pr-comment");
        debug!("Config: {:?}", config);

        // Validate repository against allowed-repositories config
        if !config.allowed_repositories.is_empty()
            && !config.allowed_repositories.contains(&self.repository)
        {
            return Ok(ExecutionResult::failure(format!(
                "Repository '{}' is not in the allowed-repositories list",
                self.repository
            )));
        }

        // Validate status against allowed-statuses config (case-insensitive)
        if !config.allowed_statuses.is_empty()
            && !config
                .allowed_statuses
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&self.status))
        {
            return Ok(ExecutionResult::failure(format!(
                "Status '{}' is not in the allowed-statuses list",
                self.status
            )));
        }

        // Validate status is a known value
        let status_int = match status_to_int(&self.status) {
            Some(v) => v,
            None => {
                return Ok(ExecutionResult::failure(format!(
                    "Invalid status '{}'. Valid statuses: {}",
                    self.status,
                    VALID_STATUSES.join(", ")
                )));
            }
        };

        // Validate file_path if present
        if let Some(ref fp) = self.file_path
            && let Err(e) = validate_file_path(fp)
        {
            return Ok(ExecutionResult::failure(format!(
                "Invalid file_path: {}",
                e
            )));
        }

        // Determine the repository name for the API call
        let repo_name = if self.repository == "self" || self.repository.is_empty() {
            ctx.repository_name
                .as_ref()
                .context("BUILD_REPOSITORY_NAME not set and repository is 'self'")?
                .clone()
        } else {
            match crate::safeoutputs::lookup_allowed_repository(
                &self.repository,
                &ctx.allowed_repositories,
            ) {
                Some(name) => name.clone(),
                None => {
                    return Ok(ExecutionResult::failure(format!(
                        "Repository alias '{}' not found in allowed repositories",
                        self.repository
                    )));
                }
            }
        };

        // Build comment content with optional prefix
        let comment_body = match &config.comment_prefix {
            Some(prefix) => format!("{}{}", prefix, self.content),
            None => self.content.clone(),
        };
        let comment_body =
            crate::agent_stats::append_stats_to_body(&comment_body, ctx, config.include_stats);

        // Build the API URL
        let url = format!(
            "{}/{}/_apis/git/repositories/{}/pullRequests/{}/threads?api-version=7.1",
            org_url.trim_end_matches('/'),
            utf8_percent_encode(project, PATH_SEGMENT),
            utf8_percent_encode(&repo_name, PATH_SEGMENT),
            self.pull_request_id,
        );
        debug!("API URL: {}", url);

        // Build the request body
        let comment_obj = serde_json::json!({
            "parentCommentId": 0,
            "content": comment_body,
            "commentType": 1
        });

        let mut thread_body = serde_json::json!({
            "comments": [comment_obj],
            "status": status_int
        });

        // Add thread context for inline comments. For an applyable `suggestion`,
        // the end anchor must span the whole target line — see `line_end_offset`.
        if let Some(ref fp) = self.file_path {
            let end_line = self.line.unwrap_or(1);
            let start_line = self.start_line.unwrap_or(end_line);
            let end_offset =
                line_end_offset(&ctx.source_directory, fp, end_line).unwrap_or_else(|| {
                    debug!(
                        "add-pr-comment: could not measure {}:{} under {}; falling back to \
                         end offset 1 (an applyable suggestion may not apply cleanly)",
                        fp,
                        end_line,
                        ctx.source_directory.display()
                    );
                    1
                });
            thread_body["threadContext"] =
                inline_thread_context(fp, start_line, end_line, end_offset);
        }

        let client = reqwest::Client::new();

        info!("Sending comment thread to PR #{}", self.pull_request_id);
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .basic_auth("", Some(token))
            .json(&thread_body)
            .send()
            .await
            .context("Failed to send request to Azure DevOps")?;

        if response.status().is_success() {
            let body: serde_json::Value = response
                .json()
                .await
                .context("Failed to parse response JSON")?;

            let thread_id = body.get("id").and_then(|v| v.as_i64()).unwrap_or(0);

            info!(
                "Comment thread added to PR #{}: thread #{}",
                self.pull_request_id, thread_id
            );

            Ok(ExecutionResult::success_with_data(
                format!(
                    "Added comment thread #{} to PR #{}",
                    thread_id, self.pull_request_id
                ),
                serde_json::json!({
                    "thread_id": thread_id,
                    "pull_request_id": self.pull_request_id,
                    "repository": repo_name,
                    "project": project,
                    "status": self.status,
                }),
            ))
        } else {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            Ok(ExecutionResult::failure(format!(
                "Failed to add comment to PR #{} (HTTP {}): {}",
                self.pull_request_id, status, error_body
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safeoutputs::ToolResult;

    #[test]
    fn test_result_has_correct_name() {
        assert_eq!(AddPrCommentResult::NAME, "add-pr-comment");
    }

    #[test]
    fn test_params_deserializes() {
        let json = r#"{"pull_request_id": 42, "content": "This is a review comment on the PR."}"#;
        let params: AddPrCommentParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.pull_request_id, 42);
        assert!(params.content.contains("review comment"));
        assert_eq!(params.repository, "self");
        assert!(params.file_path.is_none());
        assert!(params.line.is_none());
        assert_eq!(params.status, "active");
    }

    #[test]
    fn test_params_converts_to_result() {
        let params = AddPrCommentParams {
            pull_request_id: 42,
            content: "This is a test comment with enough characters.".to_string(),
            repository: "self".to_string(),
            file_path: None,
            start_line: None,
            line: None,
            status: "active".to_string(),
        };
        let result: AddPrCommentResult = params.try_into().unwrap();
        assert_eq!(result.name, "add-pr-comment");
        assert_eq!(result.pull_request_id, 42);
        assert!(result.content.contains("test comment"));
    }

    #[test]
    fn test_validation_rejects_zero_pr_id() {
        let params = AddPrCommentParams {
            pull_request_id: 0,
            content: "This is a valid comment body text.".to_string(),
            repository: "self".to_string(),
            file_path: None,
            start_line: None,
            line: None,
            status: "active".to_string(),
        };
        let result: Result<AddPrCommentResult, _> = params.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_rejects_short_content() {
        let params = AddPrCommentParams {
            pull_request_id: 42,
            content: "Too short".to_string(),
            repository: "self".to_string(),
            file_path: None,
            start_line: None,
            line: None,
            status: "active".to_string(),
        };
        let result: Result<AddPrCommentResult, _> = params.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_rejects_repository_pipeline_command() {
        let params = AddPrCommentParams {
            pull_request_id: 42,
            content: "This is a valid comment body text.".to_string(),
            repository: "##vso[task.setvariable variable=x]y".to_string(),
            file_path: None,
            start_line: None,
            line: None,
            status: "active".to_string(),
        };
        let result: Result<AddPrCommentResult, _> = params.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_rejects_line_without_file_path() {
        let params = AddPrCommentParams {
            pull_request_id: 42,
            content: "This is a valid comment body text.".to_string(),
            repository: "self".to_string(),
            file_path: None,
            start_line: None,
            line: Some(10),
            status: "active".to_string(),
        };
        let result: Result<AddPrCommentResult, _> = params.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_result_serializes_correctly() {
        let params = AddPrCommentParams {
            pull_request_id: 42,
            content: "A comment body that is definitely longer than ten characters.".to_string(),
            repository: "self".to_string(),
            file_path: Some("src/main.rs".to_string()),
            start_line: None,
            line: Some(10),
            status: "active".to_string(),
        };
        let result: AddPrCommentResult = params.try_into().unwrap();
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains(r#""name":"add-pr-comment""#));
        assert!(json.contains(r#""pull_request_id":42"#));
    }

    #[test]
    fn test_config_defaults() {
        let config = AddPrCommentConfig::default();
        assert!(config.comment_prefix.is_none());
        assert!(config.allowed_repositories.is_empty());
        assert!(config.allowed_statuses.is_empty());
    }

    #[test]
    fn test_config_deserializes_from_yaml() {
        let yaml = r#"
comment-prefix: "[Agent Review] "
allowed-repositories:
  - self
  - other-repo
allowed-statuses:
  - Active
  - Closed
"#;
        let config: AddPrCommentConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.comment_prefix, Some("[Agent Review] ".to_string()));
        assert_eq!(config.allowed_repositories, vec!["self", "other-repo"]);
        assert_eq!(config.allowed_statuses, vec!["Active", "Closed"]);
    }

    #[test]
    fn test_status_to_int_mapping() {
        // Kebab-case (canonical)
        assert_eq!(status_to_int("active"), Some(1));
        assert_eq!(status_to_int("fixed"), Some(2));
        assert_eq!(status_to_int("wont-fix"), Some(3));
        assert_eq!(status_to_int("closed"), Some(4));
        assert_eq!(status_to_int("by-design"), Some(5));
        // CamelCase (backwards compat)
        assert_eq!(status_to_int("Active"), Some(1));
        assert_eq!(status_to_int("WontFix"), Some(3));
        assert_eq!(status_to_int("ByDesign"), Some(5));
        // Invalid
        assert_eq!(status_to_int("Invalid"), None);
    }

    #[test]
    fn test_validate_file_path_rejects_traversal() {
        assert!(validate_file_path("../etc/passwd").is_err());
        assert!(validate_file_path("src/../secret").is_err());
    }

    #[test]
    fn test_validate_file_path_rejects_absolute() {
        assert!(validate_file_path("/etc/passwd").is_err());
        assert!(validate_file_path("\\windows\\system32").is_err());
    }

    #[test]
    fn test_validate_file_path_accepts_valid() {
        assert!(validate_file_path("src/main.rs").is_ok());
        assert!(validate_file_path("path/to/file.txt").is_ok());
        // ".." within a component name is not a traversal — must be accepted
        assert!(validate_file_path("releases..notes/v1.md").is_ok());
        assert!(validate_file_path("v2..beta/file.txt").is_ok());
    }

    #[test]
    fn test_line_end_offset_is_utf16_len_plus_one() {
        let dir = std::env::temp_dir().join(format!(
            "adoaw_offset_{}_{}",
            std::process::id(),
            "lineend"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let rel = "Sample.cs";
        // line 1 = "first line" (10), line 2 = "    second" (10), line 3 = "café" (4)
        std::fs::write(dir.join(rel), "first line\n    second\ncafé\n").unwrap();

        // Offset = (line length in UTF-16 code units) + 1, covering the whole line.
        assert_eq!(line_end_offset(&dir, rel, 1), Some(11));
        assert_eq!(line_end_offset(&dir, rel, 2), Some(11));
        // "café" is 4 UTF-16 code units (é is BMP) -> 5
        assert_eq!(line_end_offset(&dir, rel, 3), Some(5));
        // Out-of-range line, missing file, and non-positive line -> None (fallback).
        assert_eq!(line_end_offset(&dir, rel, 99), None);
        assert_eq!(line_end_offset(&dir, "missing.cs", 1), None);
        assert_eq!(line_end_offset(&dir, rel, 0), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_inline_thread_context_single_line() {
        // A single-line anchor: start and end on the same line; end offset spans
        // the whole line so an applied suggestion is a clean one-line replace.
        let tc = inline_thread_context("cs/src/Foo.cs", 27, 27, 74);
        assert_eq!(tc["filePath"], "/cs/src/Foo.cs");
        assert_eq!(tc["rightFileStart"]["line"], 27);
        assert_eq!(tc["rightFileStart"]["offset"], 1);
        assert_eq!(tc["rightFileEnd"]["line"], 27);
        assert_eq!(tc["rightFileEnd"]["offset"], 74);
    }

    #[test]
    fn test_inline_thread_context_multi_line() {
        // A multi-line anchor: start of the first line to end of the last line.
        // The end offset is measured from the last line, never line+1, so the
        // block is replaced without joining the following line.
        let tc = inline_thread_context("Directory.Packages.props", 9, 12, 45);
        assert_eq!(tc["filePath"], "/Directory.Packages.props");
        assert_eq!(tc["rightFileStart"]["line"], 9);
        assert_eq!(tc["rightFileStart"]["offset"], 1);
        assert_eq!(tc["rightFileEnd"]["line"], 12);
        assert_eq!(tc["rightFileEnd"]["offset"], 45);
    }

    #[test]
    fn test_validation_rejects_invalid_status() {
        let params = AddPrCommentParams {
            pull_request_id: 42,
            content: "This is a valid comment body text.".to_string(),
            repository: "self".to_string(),
            file_path: None,
            start_line: None,
            line: None,
            status: "unknown".to_string(),
        };
        let result: Result<AddPrCommentResult, _> = params.try_into();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("status must be one of"));
    }

    #[test]
    fn test_validation_accepts_valid_statuses() {
        for s in &[
            "active",
            "fixed",
            "wont-fix",
            "closed",
            "by-design",
            "Active",
            "WontFix",
        ] {
            let params = AddPrCommentParams {
                pull_request_id: 42,
                content: "This is a valid comment body text.".to_string(),
                repository: "self".to_string(),
                file_path: None,
                start_line: None,
                line: None,
                status: s.to_string(),
            };
            let result: Result<AddPrCommentResult, _> = params.try_into();
            assert!(result.is_ok(), "Expected status '{}' to be valid", s);
        }
    }

    #[test]
    fn test_allowed_statuses_case_insensitive_match() {
        // Config has "Active" but agent sends "active" (canonical lowercase) — should be allowed
        let config = AddPrCommentConfig {
            comment_prefix: None,
            allowed_repositories: Vec::new(),
            allowed_statuses: vec!["Active".to_string(), "Closed".to_string()],
            include_stats: true,
        };
        // Test the exact comparison logic extracted from execute_impl
        let status = "active";
        let matched = config
            .allowed_statuses
            .iter()
            .any(|s| s.eq_ignore_ascii_case(status));
        assert!(
            matched,
            "lowercase 'active' should match config value 'Active'"
        );
    }

    #[test]
    fn test_sanitize_content_neutralizes_repository_pipeline_command() {
        let params = AddPrCommentParams {
            pull_request_id: 42,
            content: "This is a valid comment body text.".to_string(),
            repository: "##vso[task.setvariable variable=x]y".to_string(),
            file_path: None,
            start_line: None,
            line: None,
            status: "active".to_string(),
        };
        let mut result = AddPrCommentResult {
            name: "add-pr-comment".to_string(),
            pull_request_id: params.pull_request_id,
            content: params.content,
            repository: params.repository,
            file_path: params.file_path,
            start_line: params.start_line,
            line: params.line,
            status: params.status,
        };
        result.sanitize_content_fields();
        assert!(
            result.repository.contains("`##vso[`"),
            "repository pipeline command should be neutralized with backticks: {}",
            result.repository
        );
    }
}
