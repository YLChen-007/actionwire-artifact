import javascript
import project.ProjectModel

from string kind, string verdict
where
  kind = "project-identity" and not isOpenClawProject() and verdict = "rejected"
select kind, verdict
