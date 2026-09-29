import javascript
import project.ProjectModel
import call.sinks_af

from string kind, string detail
where
  not isLobsterAIProject() and
  not exists(Function handler | lobsterAIToolHandler(handler, _, _)) and
  exists(DataFlow::CallNode sink | sinkCanonicalId(sink) = "LA-BROWSER-PAGE-GOTO") and
  kind = "shared-sink" and detail = "shape-without-project-identity"
select kind, detail
