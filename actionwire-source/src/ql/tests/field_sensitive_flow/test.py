def field_flow_sink_path(value):
    return value


def field_flow_sink_url(value):
    return value


def field_flow_sink_timeout(value):
    return value


def field_flow_sink_map_value(value):
    return value


def field_flow_sink_selector_value(value):
    return value


def field_flow_sink_whole_object(value):
    return value


def field_flow_sink_same_name(value):
    return value


def field_flow_sink_provider(value):
    return value


def field_flow_sink_rpc(value):
    return value


def field_flow_sink_unbridged(value):
    return value


def normalize_url(value):
    return value.strip().lower()


def forward_url(value):
    return normalize_url(value)


def field_flow_rpc_send(value):
    return value


def field_flow_rpc_receive(value):
    return field_flow_sink_rpc(value)


def field_flow_unbridged_send(value):
    return value


def field_flow_unbridged_receive(value):
    return field_flow_sink_unbridged(value)


def model_handler(args, config, provider):
    path = args.get("path", "")
    field_flow_sink_path(path)

    url = args["url"]
    field_flow_sink_url(forward_url(url))

    timeout = args.get("timeout", 30)
    field_flow_sink_timeout(timeout)

    map_key = args.get("map_key", "name")
    keyed = {map_key: "trusted-value"}
    field_flow_sink_map_value(keyed[map_key])

    selector = args.get("selector", "one")
    choices = {"one": "trusted-one", "two": "trusted-two"}
    field_flow_sink_selector_value(choices[selector])

    field_flow_sink_whole_object(args)

    same_name = config.get("path", "/trusted/config")
    field_flow_sink_same_name(same_name)

    provider_url = provider.get("url", "https://provider.invalid")
    field_flow_sink_provider(provider_url)

    command = args.get("command", "")
    field_flow_rpc_send(command)

    no_bridge = args.get("no_bridge", "")
    field_flow_unbridged_send(no_bridge)
