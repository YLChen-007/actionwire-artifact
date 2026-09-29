import javascript
import project.ProjectModel

from string kind, string detail
where
  not isNanoClawProject() and not exists(Function handler | nanoClawToolHandler(handler, _, _)) and
  kind = "negative" and detail = "missing-host-delivery-symbol"
select kind, detail
