import { handleAddMcpServer } from './request';
import { applyAddMcpServer } from './apply';
export function registerDeliveryAction(_action: string, _handler: unknown) {}
export function registerApprovalHandler(_action: string, _handler: unknown) {}
function handleCreateAgent() {}
function handleScheduleTask() {}
function handleCancelTask() {}
function handlePauseTask() {}
function handleResumeTask() {}
function handleUpdateTask() {}
function handleInstallPackages() {}
registerDeliveryAction('create_agent', handleCreateAgent);
registerDeliveryAction('schedule_task', handleScheduleTask);
registerDeliveryAction('cancel_task', handleCancelTask);
registerDeliveryAction('pause_task', handlePauseTask);
registerDeliveryAction('resume_task', handleResumeTask);
registerDeliveryAction('update_task', handleUpdateTask);
registerDeliveryAction('install_packages', handleInstallPackages);
registerDeliveryAction('add_mcp_server', handleAddMcpServer);
registerApprovalHandler('add_mcp_server', applyAddMcpServer);
