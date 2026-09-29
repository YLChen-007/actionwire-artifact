/**
 * @id clawgap/typescript-tool-boundaries
 * @name TypeScript external SDK and runtime tool boundaries
 * @kind table
 */

import javascript
import project.ProjectModel

from Function anchor, string toolName, string model
where projectToolBoundary(anchor, toolName, model)
select toolName as tool_name, model as form, anchor.getName() as handler_func,
  anchor.getFile().getRelativePath() as file, anchor.getLocation().getStartLine() as line,
  "-" as forwarded_body
