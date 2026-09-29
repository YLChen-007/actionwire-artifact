/**
 * @id clawgap/openclaw-project-model
 * @name active OpenClaw TypeScript project model
 * @kind table
 */

import project.ProjectModel

from string project, string adapterName
where project = activeProjectId() and adapterName = activeProjectAdapter()
select project as project_id, adapterName as adapter_name
