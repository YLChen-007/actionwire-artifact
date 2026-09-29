def prompt_dangerous_approval(command, description, **kwargs):
    return command, description, kwargs


def check_all_command_guards(command, description, callback):
    return prompt_dangerous_approval(
        command,
        description,
        approval_callback=callback,
    )
