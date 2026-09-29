import javascript
import project.ProjectModel

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName, string model |
    projectToolInventoryEntry(handler, toolName, model) and kind = "handler" and name = toolName and
    detail = model
  )
select kind, name, detail
