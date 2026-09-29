import javascript
import project.ProjectModel

from string kind, string verdict
where
  kind = "fork-identity" and not isOpenClawCNProject() and isOpenClawProject() and
  verdict = "rejected-cn-accepted-upstream"
select kind, verdict
