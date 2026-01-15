# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long

"""
Wintermute
---------

The following classes and functions are the main entry point for Wintermute,
a hardware prototype offensive Deck.

Cartridges are to be dropped in the `cartridges` folder and internal classes
should be dropped into the `core` file.
"""

import argparse

# Logging imports
import glob
import importlib
import inspect
import logging
import sys
import warnings
from datetime import datetime, timezone
from os.path import basename, dirname, isfile, join
from typing import Any, Dict

import cmd2
from cmd2 import with_argparser, with_category

# from Wintermute.database import dbBackend
from wintermute.core import Operation

warnings.filterwarnings("ignore", category=DeprecationWarning)


event_timestamp = (
    str(datetime.now(timezone.utc)).split(".")[0].replace(" ", "_").replace(":", "-")
)

# End of loggin imports
# Let's import the database stuff

# from core import Operation

# Automatically import all the cartridges so they are ready to load
modules = glob.glob(join(dirname(__file__), "cartridges/*.py"))
cartridges = [
    basename(f)[:-3] for f in modules if isfile(f) and not f.endswith("__init__.py")
]

# This will hold the objects for our operation/Pentest from here we can manipulate and
# then push into the database, easier than to constantly DB read.
CurrentOperation = Operation()

logger = logging.getLogger(__name__)


class wintermute(cmd2.Cmd):
    """Main REPL class for the Wintermute Deck.

    This class handles the REPL and automatically loading the cartridges. Cartridges
    are loaded via the `load` and `unload` commands.

    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # gotta have this or neither the plugin or cmd2 will initialize
        super().__init__(*args, auto_load_commands=False, **kwargs)

        self.prompt: str = "Wintermute> "
        # Dict containing the loaded modules so we can then unload
        self._loadedModules: Dict[Any, Any] = {}
        logging.basicConfig(
            filename="Wintermute.log",
            format="%(asctime)s %(levelname)-8s WintermuteConsole - %(message)s",
            level=logging.INFO,
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        del cmd2.Cmd.do_run_pyscript
        del cmd2.Cmd.do_run_script
        del cmd2.Cmd.do_edit
        del cmd2.Cmd.do_alias
        pass

    load_parser = cmd2.Cmd2ArgumentParser()
    load_parser.add_argument("cmds", choices=cartridges)

    @with_argparser(load_parser)
    @with_category("Cartridge Commands")
    def do_load(self, ns: argparse.Namespace) -> None:
        """Load cartridge modules.

        This function takes all the files in the cartridge folder
        and allows the user to load them into the Deck.

        Args:
            cmds (str): Cartridge module to load into the deck.

        """
        sys.path.append(join(dirname(__file__), "cartridges"))
        try:
            module = importlib.import_module(ns.cmds)
            # let's get the classes in the module
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj):
                    if name.lower() == ns.cmds.lower():
                        class_ = getattr(module, name)
                        c = class_()
                        self.register_command_set(c)
                        self._loadedModules[ns.cmds] = c
                        self.poutput(f"{ns.cmds} loaded")
        except Exception as e:
            logger.error(f"Error loading cartridge {ns.cmds}: {e}")
            print(f"Error loading cartridge {ns.cmds}: {e}")

    @with_argparser(load_parser)
    @with_category("Cartridge Commands")
    def do_unload(self, ns: argparse.Namespace) -> None:
        """Unload cartridge.

        This function will unload the cartridge that has been loaded
        by the load function, the class keeps a list of loaded modules.

        Args:
            cmds (str): Cartridge module to unload into the deck.

        """
        try:
            self.unregister_command_set(self._loadedModules[ns.cmds])
            del self._loadedModules[ns.cmds]
            self.poutput(f"{ns.cmds} unloaded")
        except Exception as e:
            logger.error(f"Error unloading cartridge {ns.cmds}: {e}")
            print(f"Error unloading cartridge {ns.cmds}: {e}")

    def do_checkThings(self) -> None:
        pass

    manageOperators_parser = cmd2.Cmd2ArgumentParser()
    manageOperators_group = manageOperators_parser.add_mutually_exclusive_group(
        required=True
    )
    manageOperators_group.add_argument(
        "-a", "--add", action="store_true", help="Add analyst into the assessment"
    )
    manageOperators_group.add_argument(
        "-d", "--delete", action="store_true", help="Delete analyst from the assessment"
    )
    manageOperators_parser.add_argument(
        "-n", "--name", action="store", help="Operator Name"
    )
    manageOperators_parser.add_argument(
        "-l", "--alias", action="store", help="Alias of the operator"
    )
    manageOperators_parser.add_argument(
        "-e", "--email", action="store", help="Email of the operator"
    )

    @with_argparser(manageOperators_parser)
    @with_category("Operation Commands")
    def do_ManageOperators(self, args: argparse.Namespace) -> None:
        """Manage Analysts for the assessment

        This will allow us to manage analysts in the engagement for reporting and tasking.
        """
        if args.add:
            name = "Default Analyst" if not args.name else args.name
            alias = "alias@" if not args.alias else args.alias
            email = "alias@exploit.ninja" if not args.email else args.email
            CurrentOperation.addAnalyst(name=name, userid=alias, email=email)
            CurrentOperation.save()
            logging.info(
                f"Added Analyst {name} with alias {alias} and email {email} to the assessment"
            )

        if args.delete:
            name = None if not args.name else args.name
            alias = None if not args.alias else args.alias
            email = None if not args.email else args.email
            CurrentOperation.save()
        pass

    operation_parser = cmd2.Cmd2ArgumentParser()
    operation_parser_group = operation_parser.add_mutually_exclusive_group()
    operation_parser_group.add_argument(
        "-c", "--create", action="store", type=str, help="Create operation name"
    )
    operation_parser_group.add_argument(
        "-d", "--delete", action="store", help="Delete the operation"
    )
    operation_parser.add_argument(
        "-s", "--startdate", action="store", help="Start date of the operation"
    )
    operation_parser.add_argument(
        "-e", "--enddate", action="store", help="End date of the operation"
    )

    @with_argparser(operation_parser)
    @with_category("Operation Commands")
    def do_ManageOperation(self, args: argparse.Namespace) -> None:
        """Manage operations (Create, Delete, Start date and End date)"""
        if args.create:
            CurrentOperation.dbOperation = args.create

        if args.startdate:
            CurrentOperation.start_date = datetime.strptime(
                args.startdate, "%m/%d/%Y"
            ).strftime("%m/%d/%Y")

        if args.enddate:
            CurrentOperation.end_date = datetime.strptime(
                args.enddate, "%m/%d/%Y"
            ).strftime("%m/%d/%Y")

        pass

    @cmd2.with_category("Operation Commands")
    def do_getCurrentOperation(self, args: Any) -> None:
        print(f"Operation name is {CurrentOperation.operation_name}")
        # print(CurrentOperation.toJSON())
        pass

    def do_saveOperation(self, args: Any) -> None:
        CurrentOperation.save()

    operation_load_parser = cmd2.Cmd2ArgumentParser()
    operation_load_parser.add_argument(
        "-o",
        "--operation",
        action="store",
        required=True,
        help="name of the operation to load",
    )

    @with_argparser(operation_load_parser)
    @cmd2.with_category("Operation Commands")
    def do_loadOperation(self, args: argparse.Namespace) -> None:
        if args.operation:
            CurrentOperation.dbOperation = args.operation
            CurrentOperation.load()
        pass

    @cmd2.with_category("Operation Commands")
    def do_printOperation2Screen(self, args: Any) -> None:
        """Print current database tree as json into the screen"""
        print(CurrentOperation.to_dict())


def main() -> int:
    ono = wintermute()
    ono.cmdloop("Welcome to Wintermute Deck REPL. Type help or ? to list commands.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
