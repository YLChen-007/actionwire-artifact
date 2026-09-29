/**
 * @id clawgap/openclaw-sinks
 * @name OpenClaw TypeScript dangerous sink points
 * @kind table
 */

import javascript
import project.ProjectModel
import call.sinks_af

from DataFlow::CallNode call
where is_sink_af(call) and isCoreLocation(call.getLocation())
select call.getLocation().getFile().getRelativePath() as file,
  call.getLocation().getStartLine() as line, sinkLabel(call) as sink
