const fieldFlowSinkPath = (value: unknown) => value;
const fieldFlowSinkUrl = (value: unknown) => value;
const fieldFlowSinkTimeout = (value: unknown) => value;
const fieldFlowSinkMapValue = (value: unknown) => value;
const fieldFlowSinkSelectorValue = (value: unknown) => value;
const fieldFlowSinkWholeObject = (value: unknown) => value;
const fieldFlowSinkSameName = (value: unknown) => value;
const fieldFlowSinkProvider = (value: unknown) => value;
const fieldFlowSinkRpc = (value: unknown) => value;
const fieldFlowSinkUnbridged = (value: unknown) => value;

const normalizeUrl = (value: string) => value.trim().toLowerCase();
const forwardUrl = (value: string) => normalizeUrl(value);

const fieldFlowRpcSend = (value: unknown) => value;
const fieldFlowRpcReceive = (value: unknown) => fieldFlowSinkRpc(value);
const fieldFlowUnbridgedSend = (value: unknown) => value;
const fieldFlowUnbridgedReceive = (value: unknown) => fieldFlowSinkUnbridged(value);

export const modelHandler = (
  args: Record<string, unknown>,
  config: Record<string, unknown>,
  provider: Record<string, unknown>,
) => {
  const path = args.path;
  fieldFlowSinkPath(path);

  const url = args["url"] as string;
  fieldFlowSinkUrl(forwardUrl(url));

  const timeout = args.timeout;
  fieldFlowSinkTimeout(timeout);

  const mapKey = args.mapKey as string;
  const keyed: Record<string, string> = { [mapKey]: "trusted-value" };
  fieldFlowSinkMapValue(keyed[mapKey]);

  const selector = args.selector as string;
  const choices: Record<string, string> = { one: "trusted-one", two: "trusted-two" };
  fieldFlowSinkSelectorValue(choices[selector]);

  fieldFlowSinkWholeObject(args);

  const sameName = config.path;
  fieldFlowSinkSameName(sameName);

  const providerUrl = provider.url;
  fieldFlowSinkProvider(providerUrl);

  const command = args.command;
  fieldFlowRpcSend(command);

  const noBridge = args.noBridge;
  fieldFlowUnbridgedSend(noBridge);
};

void fieldFlowRpcReceive;
void fieldFlowUnbridgedReceive;
