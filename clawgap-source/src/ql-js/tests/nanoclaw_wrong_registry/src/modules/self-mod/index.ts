import { handleAddMcpServer } from './request';
function registerDeliveryAction(_action: string, _handler: unknown) {}
registerDeliveryAction('install_packages', handleAddMcpServer);
