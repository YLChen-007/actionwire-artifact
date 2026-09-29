import javascript
import project.ProjectModel

from string kind, string detail
where
  not isCodeGProject() and kind = "negative" and detail = "wrong-project-rejected"
select kind, detail
