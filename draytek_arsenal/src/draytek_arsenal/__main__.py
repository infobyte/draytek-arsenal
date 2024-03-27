import os
import argparse
import importlib.util
import draytek_arsenal
from draytek_arsenal.commands.base import Command
from typing import List, Type

def load_commands(commands_dir: str) -> List[Type[Command]]:
    """
    Dynamically loads all the subclasses of Command from the files in the commands directory
    """
    commands = []
    if os.path.exists(commands_dir):
        for file_name in os.listdir(commands_dir):
            if file_name.endswith(".py"):
                module_name = file_name[:-3]  # Remove the .py extension
                module_path = os.path.join(commands_dir, file_name)
                spec = importlib.util.spec_from_file_location(module_name, module_path)

                if spec is None or spec.loader is None:
                    raise RuntimeError(f"Can't load spec from {file_name}")

                module = importlib.util.module_from_spec(spec)

                # Load the module
                spec.loader.exec_module(module)

                for name in dir(module):
                    obj = getattr(module, name)
                    if isinstance(obj, type) and issubclass(obj, Command) and obj != Command:
                        commands.append(obj)

    return commands

def create_parser(command: Command) -> argparse.ArgumentParser:
    """
    Creates a arguments parser for a specific command
    """
    parser = argparse.ArgumentParser(
        description=command.description(),
        prog=command.name()
    )
    for arg in command.args():
        parser.add_argument(*arg["flags"], **arg["kwargs"])
    return parser

def main(commands):
    parser = argparse.ArgumentParser(
        description="Draytek firmware analysis tools",
        prog="draytek-tools"
    )
    parser.add_argument(
        "command",
        choices=[command.name() for command in commands],
        help="The command to execute"
    )

    args, remaining_argv = parser.parse_known_args()

    # Get the selected command
    selected_command = next((command for command in commands if command.name() == args.command), None)
    if selected_command is not None:
        command_parser = create_parser(selected_command)
        command_args = command_parser.parse_args(remaining_argv)
        selected_command.execute(command_args)

    else:
        print("Invalid command. Use --help for usage information.")

if __name__ == "__main__":
    commands = load_commands(os.path.dirname(draytek_arsenal.commands.__file__))
    main(commands)
