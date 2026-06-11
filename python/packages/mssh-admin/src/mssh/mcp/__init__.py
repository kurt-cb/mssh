"""mssh-mcp — MCP server exposing the CA's read-only admin API.

Tools (v1, read-only):
  status         — walk the adoption journey, same data as mssh-admin status
  server_list    — list enrolled servers, optionally filtered by group
  user_list      — list enrolled users with their keys + policies
  user_inspect   — full detail on one user
  audit_search   — recent authorize decisions, filterable
  admin_list     — list enrolled admins

Auth: connects to the CA over mTLS using the same admin client config
mssh-admin reads (~/.mssh-admin/config), so a single set of operator
credentials works for both interfaces.

Write tools (server_add, user_add, policy_add, key-rotate, …) are
deliberately out of scope for v1 — those carry a trust delegation that
needs its own design conversation (see design/future-ideas.md §12).

Design: §12 (mssh-mcp).
"""
