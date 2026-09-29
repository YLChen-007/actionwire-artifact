import httpx


def tool(name, description, schema):
    return lambda function: function


class ChannelRuntimeClient:
    async def _request(self, path, payload):
        async with httpx.AsyncClient() as client:
            return await client.post(path, json=payload)

    async def create_task(self, *, title):
        return await self._request("/tasks", {"title": title})

    async def download_artifact(self, *, artifact_id):
        async with httpx.AsyncClient() as client:
            return await client.post(
                "/artifacts/download",
                json={"artifact_id": artifact_id},
            )


def create_channel_runtime_mcp_server(runtime_client):
    @tool("create_channel_task", "Create task", {"title": str})
    async def create_channel_task(args):
        title = args.get("title")
        return await runtime_client.create_task(title=title)

    @tool("stage_channel_artifact_to_workspace", "Download artifact", {"artifact_id": str})
    async def stage_channel_artifact_to_workspace(args):
        artifact_id = args.get("artifact_id")
        return await runtime_client.download_artifact(artifact_id=artifact_id)

    async def unrelated_callback(args):
        return args

    return [create_channel_task, stage_channel_artifact_to_workspace]
