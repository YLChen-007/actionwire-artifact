/**
 * @id clawgap/openclaw-tool-handlers
 * @name TypeScript local tool handlers and external tool boundaries
 * @kind table
 */

import javascript
import project.ProjectModel

from Function anchor, string toolName, string model
where projectToolInventoryEntry(anchor, toolName, model)
select toolName as tool_name, model as form, anchor.getName() as handler_func,
  anchor.getFile().getRelativePath() as file, anchor.getLocation().getStartLine() as line,
  "-" as forwarded_body
