/**
 * @id clawgap/project-model
 * @name active Python benchmark project model
 * @description The pipeline requires exactly one active project adapter per CodeQL database.
 * @kind table
 * @tags clawgap
 */

import project.ProjectModel

from string project, string adapterName
where project = activeProjectId() and adapterName = activeProjectAdapter()
select project as project_id, adapterName as adapter_name
