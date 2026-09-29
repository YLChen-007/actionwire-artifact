from pathlib import Path


def check(value):
    return bool(value)


def check_pair(value):
    return bool(value), "detail"


def resolve(value):
    return value


def has_binary_extension(value):
    return str(value).endswith(".bin")


def direct_condition(value):
    if check(value):
        return
    consume(value)


def assigned_result(value):
    result = check(value)
    if result:
        return
    consume(value)


def tuple_unpacked_result(value):
    matched, detail = check_pair(value)
    if matched:
        return detail
    consume(value)


def mapping_truthiness(delivery):
    extra = delivery.get("deliver_extra", {})
    repo = extra.get("repo", "")
    pr_number = extra.get("pr_number", "")
    if not repo or not pr_number:
        return
    consume(repo, pr_number)


def nested_constructor(value):
    path = Path(value)
    if path.is_file():
        return
    consume(path)


def nested_producer(value):
    resolved = resolve(value)
    if has_binary_extension(resolved):
        return
    consume(value)


def consume(*values):
    return values
