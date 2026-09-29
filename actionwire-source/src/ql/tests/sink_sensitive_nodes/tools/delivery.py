def delivery_sensitive(session, url, payload, headers, timeout):
    session.post(url, headers=headers, json=payload, timeout=timeout)
    session.put(url, headers=headers, json=payload, timeout=timeout)


def matrix_sensitive(client, room_id, event_type, content):
    client.send_message_event(room_id, event_type, content)


def mattermost_sensitive(client, payload):
    client._api_post("posts", payload)


def slack_sensitive(client, kwargs):
    client.chat_postMessage(**kwargs)
