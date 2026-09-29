async def materialize_skill(name, body):
    with open(name, "w") as handle:
        handle.write(body)
    return name
