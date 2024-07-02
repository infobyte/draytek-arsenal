from draytek_arsenal.commands.base import Command
from typing import Any, Dict, List
import docker
import os

MIPS_TOOLS_IMAGE = "draytek-arsenal"

class MipsMergeCommand(Command):

    @staticmethod
    def name() -> str:
        return "mips_merge"

    @staticmethod
    def description() -> str:
        return "Merge two ELF MIPS relocatable files"

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["first_input"], "kwargs": {"type": str, "help": "First input file"}},
            {"flags": ["second_input"], "kwargs": {"type": str, "help": "Second input file"}},
            {"flags": ["output"], "kwargs": {"type": str, "help": "Output file"}},
        ]

    
    @staticmethod
    def execute(args):
        client = docker.from_env()
        
        try:
            # Check if the image exists
            _ = client.images.get(MIPS_TOOLS_IMAGE)
            print(f"[+] Image '{MIPS_TOOLS_IMAGE}' is present.")

            container_arg = " ".join(["merge", args.first_input, args.second_input, args.output])
            
            print(f"[*] Running mips_tools with: '{container_arg}'")
            # Run a container from the image with the specified argument
            client.containers.run(
                MIPS_TOOLS_IMAGE,
                container_arg,
                volumes=[f"{os.getcwd()}:/shared"]
            )

            print("[+] Compiled with success. Bye.")

        except docker.errors.ImageNotFound:
            print(f"[x] Image '{MIPS_TOOLS_IMAGE}' not found. Please build or download the image.")

        except docker.errors.ContainerError as e:
            print(f"[x] Conteiner returns with an error:\n{e}")

        except docker.errors.APIError as e:
            print(f"[x] {str(e)}")
