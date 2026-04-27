package claudecode

// Fixtures live as Go string consts (instead of testdata/*.json files)
// because the repo's root .gitignore excludes any testdata/ directory.
// Embedding the fixtures keeps the tests reproducible across checkouts
// without needing `git add -f` on ignored paths.

const fixUserSettingsWithOktsec = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/oktsec hook --port 9090"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/oktsec hook --port 9090"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "echo hello"
          }
        ]
      }
    ]
  }
}
`

const fixUserSettingsNoOktsec = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/some-other/lint --tool {tool}"
          }
        ]
      }
    ]
  }
}
`

const fixClaudeJSON = `{
  "mcpServers": {
    "oktsec-gateway": {
      "type": "http",
      "url": "http://127.0.0.1:9090/mcp"
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  },
  "projects": {
    "/PROJECT_DIR_PLACEHOLDER": {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        }
      }
    }
  }
}
`

const fixAgentCodeReviewer = "---\n" +
	"name: code-reviewer\n" +
	"description: Reviews diffs for security issues\n" +
	"tools:\n" +
	"  - Read\n" +
	"  - Grep\n" +
	"disallowedTools:\n" +
	"  - Bash\n" +
	"mcpServers:\n" +
	"  - github\n" +
	"permissionMode: confirmActions\n" +
	"hooks:\n" +
	"  PostToolUse: []\n" +
	"---\n\n" +
	"# Code reviewer\n\n" +
	"Body prose ignored by the parser.\n"

const fixAgentNoFrontmatter = "# general-purpose\n\n" +
	"This file has no YAML frontmatter; the inventory should still surface\n" +
	"it under the file basename.\n"

// fixtureSources maps the filename test cases use to its embedded
// content, so existing tests that say `read fixture X` keep their
// readable form.
var fixtureSources = map[string]string{
	"user_settings_with_oktsec.json": fixUserSettingsWithOktsec,
	"user_settings_no_oktsec.json":   fixUserSettingsNoOktsec,
	"claude_json.json":               fixClaudeJSON,
	"agent_code_reviewer.md":         fixAgentCodeReviewer,
	"agent_no_frontmatter.md":        fixAgentNoFrontmatter,
}
