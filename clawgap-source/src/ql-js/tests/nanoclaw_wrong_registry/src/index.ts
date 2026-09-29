import { createChannelDeliveryAdapter } from './channels/channel-registry';
function setDeliveryAdapter(_adapter: unknown) {}
setDeliveryAdapter(createChannelDeliveryAdapter());
