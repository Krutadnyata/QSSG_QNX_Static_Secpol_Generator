import json
from enum import Enum
from pycparser import parse_file, c_ast, c_generator
import argparse
import subprocess
import os


class FunctionCallExtractor(c_ast.NodeVisitor):
    def __init__(self, ast):
        self.ast = ast
        self.calls = []
        self.visited_functions = set()
        self.function_prototypes = {}
        self.generator = c_generator.CGenerator()

    def visit_FuncCall(self, node):
        func_name = self._get_func_name(node)
        if func_name not in self.visited_functions:
            func_args = self._get_func_args(node)
            self.calls.append((func_name, func_args))
            self.generic_visit(node)
            self.function_by_name(func_name)

    def _get_func_name(self, node):
        if isinstance(node.name, c_ast.ID):
            return node.name.name
        elif isinstance(node.name, c_ast.StructRef):
            return self._get_func_name(node.name)
        return "[Unknown Function]"

    def _get_func_args(self, node):
        func_args = []
        if node.args:
            for expr in node.args.exprs:
                func_args.append(self.generator.visit(expr))
        return func_args

    def function_by_name(self, func_name):
        for ext in self.ast.ext:
            if isinstance(ext, c_ast.FuncDef) and ext.decl.name == func_name:
                self.visited_functions.add(func_name)
                self.visit(ext)
                break


def process_c_file(c_file_path, entry_func="main"):
    ast = parse_file(c_file_path, use_cpp=False)
    extractor = FunctionCallExtractor(ast)
    extractor.function_by_name(entry_func)  # Start with entry function
    return extractor.calls


def get_the_preprocessed_file(file_path=None, qcc_path=None, include_path=None):
    command = ['./preprocessed_file.sh', file_path, qcc_path, include_path]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == -1:
        print("Error:", result.stderr)
        exit(1)


class SecpolGenerator:
    path_to_abilities_file = "./Abilities.json"
    path_to_output_abilities_file = "./output/secpol_abilities.txt"
    path_to_suggestion_file = "./output/suggestion.txt"
    output_directory = "./output"

    def __init__(self):
        self.secpol_type = None
        self.fcall_with_args_as_nonroot = None
        self.fcall_list_run_as_nonroot = None
        self.fcall_with_args_as_root = None
        self.fcall_list_run_as_root = None
        self.function_call_list = []
        self.function_with_args = {}
        self.abilities_list = self.provide_abilities_list()
        self.to_suggestion_file = ""
        self.to_secpol_file = ""

    def provide_abilities_list(self):
        with open(self.__class__.path_to_abilities_file, 'r') as file:
            return json.load(file)

    def __separate_root_nonroot_func_calls(self, calls=None):
        running_root = True
        r_idx = 0
        nr_idx = 0
        for function, argument in calls:
            argument.insert(0, function)
            if running_root is True:
                self.fcall_list_run_as_root.append(function)
                self.fcall_with_args_as_root[r_idx] = argument
                r_idx += 1
            else:
                self.fcall_list_run_as_nonroot.append(function)
                self.fcall_with_args_as_nonroot[nr_idx] = argument
                nr_idx += 1
            if function == 'set_ids_from_arg':
                running_root = False
        print("function while running as root")
        print(self.fcall_list_run_as_root)
        print("function while running as non root")
        print(self.fcall_list_run_as_nonroot)

    def add_to_suggestion(self, str_to_add):
        self.to_suggestion_file += str_to_add
        self.to_suggestion_file += "\n"

    def add_to_secpol(self, str_to_add):
        self.to_secpol_file += str_to_add
        self.to_secpol_file += "\n"

    def get_function_call(self, function_with_args):
        function_call = function_with_args[0] + "("
        for i in function_with_args[1:]:
            function_call += i
            function_call += ","
        function_call = function_call[:-1]
        function_call += ");"
        return function_call

    def event_ability(self, function_with_args: list):
        class PrivEventEnum(Enum):
            PROCMGR_EVENT_SYSCONF = 0x00010000
            PROCMGR_EVENT_CONFSTR = 0x00020000
            PROCMGR_EVENT_DAEMON_DEATH = 0x00040000
            PROCMGR_EVENT_CONTIG_ALLOC_FAIL = 0x00080000
            PROCMGR_EVENT_PROCESS_DEATH = 0x00100000
            PROCMGR_EVENT_PROCESS_CREATE = 0x00400000

        for event in PrivEventEnum:
            if event == function_with_args[1]:
                if "procmgr_event_trigger" in function_with_args:
                    self.add_to_secpol("event")
                else:
                    self.add_to_secpol(''.join(["event:", function_with_args[2]]))
                break

    def interrupt_ability(self, function_with_args: list):
        _NTO_INTR_QUERY_SOURCE = "0x00000001U"
        _NTO_INTR_QUERY_HANDLER = "0x00000000U"

        if any(s.startswith("InterruptQuery") for s in function_with_args):
            if _NTO_INTR_QUERY_SOURCE in function_with_args[1]:
                # in InterruptQuery intr no /id is second parameter
                if function_with_args[2].isdecimal():
                    comment = "#Provide the after interrupt:<interrupt number/id> corresponding function: " + \
                              self.get_function_call(function_with_args)
                else:
                    comment = "#Required Interrupt"
                self.add_to_secpol(''.join(["interrupt:", function_with_args[2], comment]))
            elif _NTO_INTR_QUERY_HANDLER in function_with_args:
                return
            else:
                comment = "#Not able to retrieve type (1st parameter) of: " + self.get_function_call(function_with_args) \
                          + (": If type is _NTO_INTR_QUERY_SOURCE then add ability => interrupt:id(2nd parameter of "
                             "function) to secpol")
                self.add_to_suggestion(''.join([comment, ]))
        elif any(s.startswith("InterruptAttach") for s in function_with_args):
            if function_with_args[1].isdigit():
                # in InterruptQuery intr number is first parameter

                comment = "#Provide the after interrupt:<interrupt number/id> corresponding function: " + \
                          self.get_function_call(function_with_args)
            else:
                comment = "#Required Interrupt"
            self.add_to_secpol(''.join(["interrupt:", function_with_args[1], comment]))

    def memory_abilities(self, function_with_args: list):
        """
        :description: adds the memory related secpol abilities
        :param function_with_args: list which contains function name followed by its argument
        :return: None
        """
        #shm_ctl flags
        SHMCTL_ANON = "0x00000001"
        SHMCTL_PHYS = "0x00000002"
        SHMCTL_TYMEM = "0x00002000"

        #mmap flags
        MAP_FIXED = "0x00000010"
        MAP_PHYS = "0x00010000"
        MAP_ANON = "0x00080000"

        #mmap prot
        PROT_WRITE = "0x00000200"
        PROT_EXEC = "0x00000400"

        if "mmap_device_io" == function_with_args[0]:
            funct = ''.join([function_with_args[0], "(", function_with_args[1], ",", function_with_args[2], ");"])
            self.add_to_suggestion(''.join(["Please use mmap() function instead of : ", funct, "This function is only "
                                                                                               "provided for backward "
                                                                                               "compatibility"]))
            return
        if "shm_ctl" in function_with_args and SHMCTL_PHYS in function_with_args[2] and not \
                (SHMCTL_ANON in function_with_args[2] or SHMCTL_TYMEM in function_with_args[2]):
            start_addr = function_with_args[3]
            end_addr = int(start_addr) + int(function_with_args[4])
            self.add_to_secpol(''.join(["mem_phys:", str(start_addr), "-", str(end_addr), "", "#Please update the addr"
                                                                                              "with ram section name "
                                                                                              "inside which this "
                                                                                              "address occur."]))
        if function_with_args[0].startswith("mmap") and MAP_PHYS in function_with_args[4] and \
                not (MAP_ANON in function_with_args[4]):
            start_addr = function_with_args[1]
            end_addr = int(start_addr) + int(function_with_args[2])
            self.add_to_secpol(''.join(["mem_phys:", str(start_addr), "-", str(end_addr), "", "#Please update the "
                                                                                              "addr with ram section "
                                                                                              "name inside which "
                                                                                              "this address occur."]))
        if function_with_args[0].startswith("mmap") and MAP_FIXED in function_with_args[4]:
            start_addr = function_with_args[1]
            end_addr = int(start_addr) + int(function_with_args[2])
            self.add_to_secpol(''.join(["map_fixed:", str(start_addr), "-", str(end_addr), "", "#Please update the "
                                                                                               "addr with ram section "
                                                                                               "name inside which "
                                                                                               "this address occur."]))
        if (function_with_args[0].startswith("mmap") or function_with_args[0].startswith("mprotect")) \
                and PROT_EXEC in function_with_args[3]:
            start_addr = function_with_args[1]
            end_addr = int(start_addr) + int(function_with_args[2])
            if PROT_WRITE in function_with_args[3]:
                self.add_to_secpol(''.join(["prot_write_and_exec:", str(start_addr), "-", str(end_addr)]))
            else:
                self.add_to_secpol(''.join(["prot_exec:", str(start_addr), "-", str(end_addr)]))

        if function_with_args[0].startswith("mlock"):
            self.add_to_secpol(''.join(["mem_lock", "#Provide subrange if using mlock"]))

    def setgid_ability(self, func_args_list):
        if func_args_list[0].startswith("setgid") or func_args_list[0].startswith("setegid"):
            if func_args_list[1].isdecimal():
                comment = ""
            else:
                comment = "#Please provide actual integer value of gid getting set by function: " + \
                          self.get_function_call(func_args_list) + "=> setgid:<gid>"
            self.add_to_secpol(''.join(["setgid:", func_args_list[1], comment]))
        elif func_args_list[0].startswith("setregid"):
            if func_args_list[1].isdecimal() and func_args_list[2].isdecimal():
                comment = ""
            else:
                comment = "#Please provide actual integer value of gid getting set by function: " + \
                          self.get_function_call(func_args_list) + "=> setgid:<rgid,egid>"
            self.add_to_secpol(''.join(["setgid:", func_args_list[1], func_args_list[2], comment]))
        else:
            comment = "#Please provide actual integer value of gid getting set by function: " + \
                      self.get_function_call(func_args_list) + "=> setgid:<gid>"
            self.add_to_secpol(''.join(["setgid:", func_args_list[2], comment]))

    def setuid_ability(self, func_args_list):
        if func_args_list[0].startswith("setuid") or func_args_list[0].startswith("seteuid"):
            if func_args_list[1].isdecimal():
                comment = ""
            else:
                comment = "#Please provide actual integer value of uid getting set by function: " + \
                          self.get_function_call(func_args_list) + "=> setuid:<uid>"
            self.add_to_secpol(''.join(["setuid:", func_args_list[1], comment]))
        else:
            if func_args_list[1].isdecimal() and func_args_list[2].isdecimal():
                comment = ""
            else:
                comment = "#Please provide actual integer value of uid getting set by function: " + \
                          self.get_function_call(func_args_list) + "=> setuid:<ruid,euid>"
            self.add_to_secpol(''.join(["setuid:", func_args_list[1], func_args_list[2], comment]))

    def settypeid_ability(self, func_args_list):
        if func_args_list[0].startswith("procmgr_set_type_id"):
            if func_args_list[1].isdecimal():
                comment = ""
            else:
                comment = " #Please provide the actual type id (integer value) after settypeid for function:" + \
                          self.get_function_call(func_args_list)
            self.add_to_secpol(''.join(["settypeid:", func_args_list[1], comment]))
        elif func_args_list[0].startswith("posix_spawnattr_settypeid"):
            if func_args_list[2].isdecimal():
                comment = ""
            else:
                comment = " #Please provide the actual type id (integer value) after settypeid for function:" + \
                          self.get_function_call(func_args_list)
            self.add_to_secpol(''.join(["settypeid:", func_args_list[2], comment]))
        else:
            comment = self.get_function_call(func_args_list) + ("If this function set type id for child in attribute "
                                                                "please add settypeid:<type_id> secpol policy")
            self.add_to_suggestion(comment)

    def signal_ability(self, func_args_list):
        if func_args_list[0].startswith("SignalKillSigval") or func_args_list[0].startswith("SignalKill"):
            if func_args_list[4].isdecimal():
                comment = ""
            else:
                comment = " #Please provide the actual signal value used in function: " + \
                          self.get_function_call(func_args_list)
            self.add_to_secpol(''.join(["signal:", func_args_list[4], comment]))
        else:
            if func_args_list[2].isdecimal():
                comment = ""
            else:
                comment = " #Please provide the actual signal value used in function: " + \
                          self.get_function_call(func_args_list)
                self.add_to_secpol(''.join(["signal:", func_args_list[2], comment]))

    def abilities_for_thread_ctl(self, function_with_args):
        _NTO_TCTL_IO_PRIV = "1"
        _NTO_TCTL_IO_ = "14"
        _NTO_TCTL_IO_LEVEL = "19"
        _NTO_IO_LEVEL_1 = "2u"
        _NTO_IO_LEVEL_2 = "3u"
        _NTO_TCTL_RUNMASK = "4"
        _NTO_TCTL_RUNMASK_GET_AND_SET = "6"
        _NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT = "10"
        _NTO_TCTL_NAME = "11"
        _NTO_TCTL_THREADS_HOLD = "2"
        _NTO_TCTL_THREADS_CONT = "3"
        _NTO_TCTL_ONE_THREAD_HOLD = "8"
        _NTO_TCTL_ONE_THREAD_CONT = "9"

        if function_with_args[0].startswith("ThreadCtlExt"):
            cmd = function_with_args[3]
            level = function_with_args[4]
        else:
            cmd = function_with_args[1]
            level = function_with_args[2]
        if _NTO_TCTL_IO_ in cmd or (_NTO_TCTL_IO_LEVEL in cmd and _NTO_IO_LEVEL_1 in level):
            self.add_to_secpol("io:0")
        if _NTO_TCTL_IO_PRIV in cmd or (_NTO_TCTL_IO_LEVEL in cmd and _NTO_IO_LEVEL_2 in level):
            self.add_to_secpol("io:1")
            comment = "io:1 is privilege ability required for" + self.get_function_call(function_with_args) + \
                      ("This thread then runs at Exception Level 1. This is a major security vulnerability. Please "
                       "refer QNX documentation")
            self.add_to_suggestion(comment)
        if _NTO_TCTL_RUNMASK in cmd or _NTO_TCTL_RUNMASK_GET_AND_SET in cmd or _NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT in cmd:
            comment = "xprocess_debug:<userid_of_process> is privilege ability required for" + \
                      self.get_function_call(function_with_args) + \
                      "This will let one proces changes runmask of other process"
            self.add_to_suggestion(comment)
        if _NTO_TCTL_NAME in cmd:
            comment = "#Please provide the user_id of the process which name is getting read by function:" + \
                      self.get_function_call(function_with_args) + "after xprocess_query : xprocess_query:<user_id>"
            self.add_to_secpol(''.join(["xprocess_query", comment]))
        if function_with_args[0].startswith("ThreadCtlExt"):
            SIGSTOP = 23
            SIGCONT = 25
            if _NTO_TCTL_THREADS_HOLD in cmd or _NTO_TCTL_ONE_THREAD_HOLD in cmd:
                self.add_to_secpol(''.join(["signal:", SIGSTOP, " #SIGSTOP"]))
            if _NTO_TCTL_THREADS_CONT in cmd or _NTO_TCTL_ONE_THREAD_CONT in cmd:
                self.add_to_secpol(''.join(["signal:", SIGCONT, " #SIGCONT"]))

    def xprocess_query_ability(self, function_with_args: list):
        CLOCK_REALTIME = "0"
        CLOCK_MONOTONIC = "2"
        CLOCK_PROCESS_CPUTIME_ID = "3"
        CLOCK_THREAD_CPUTIME_ID = "4"
        if "ClockTime" in function_with_args[0] or "clock_gettime" in function_with_args[0]:
            if CLOCK_REALTIME == function_with_args[1] or CLOCK_MONOTONIC == function_with_args[1] or \
                    CLOCK_PROCESS_CPUTIME_ID == function_with_args[1] or \
                    CLOCK_THREAD_CPUTIME_ID == function_with_args[1]:
                return
            else:
                comment = "#Please provide the user_id of the process which clock is getting read by function:" + \
                          self.get_function_call(function_with_args) + "after xprocess_query : xprocess_query:<user_id>"
                self.add_to_secpol(''.join(["xprocess_query", comment]))
        if function_with_args[0].startswith("TimerInfo"):
            comment = "#Please provide the user_id of the process which gets the timer information by function:" + \
                      self.get_function_call(function_with_args) + "after xprocess_query : xprocess_query:<user_id>."
            self.add_to_secpol(''.join(["xprocess_query", comment]))

    def check_the_required_abilities(self, is_root_ability, function_with_args: dict):
        self.add_to_secpol(''.join(["allow ", self.secpol_type, " self:ability {"]))

        if is_root_ability == 0:
            self.add_to_secpol("nonroot,")

        for ability, req_functions in self.abilities_list.items():
            for func_args_list in function_with_args.values():
                for req_func in req_functions:
                    if any(s.startswith(req_func) for s in func_args_list):
                        self.add_to_secpol(ability)

        for func_args_list in function_with_args.values():
            if func_args_list[0].startswith("clock_settime") or func_args_list[0].startswith("settimeofday") or \
                    func_args_list[0].startswith("ClockAdjust") or func_args_list[0].startswith("ClockTime"):
                comment = "Please add the ability clockset:<time in nanosecond> for used function:" + \
                          self.get_function_call(func_args_list)
                self.add_to_suggestion(comment)
            elif "clock_gettime" in func_args_list[0] or "ClockTime" in func_args_list[0] or "ConnectFlags" in \
                    func_args_list[0]:
                self.xprocess_query_ability(func_args_list)
            elif "confstr" in func_args_list[0]:
                self.add_to_secpol(''.join(["confset:", func_args_list[1]]))
            elif func_args_list[0].startswith("InterruptAttach") or func_args_list[0].startswith("InterruptQuery"):
                # "_NTO_INTR_QUERY_SOURCE" in func_args_list:
                self.interrupt_ability(func_args_list)
            elif func_args_list[0].startswith("mlock") or func_args_list[0].startswith("mmap") or \
                    "shm_ctl" in func_args_list:
                self.memory_abilities(func_args_list)
            elif func_args_list[0].startswith("posix_spawnattr_setflags"):
                POSIX_SPAWN_NEWAPP = "0x10000000"
                if POSIX_SPAWN_NEWAPP in func_args_list[2]:
                    self.add_to_secpol("child_newapp")
            elif func_args_list[0].startswith("procmgr_ability"):
                PROCMGR_AOP_ALLOW = "0x00020000u"
                PROCMGR_AOP_SUBRANGE = "0x00040000u"
                if PROCMGR_AOP_ALLOW in func_args_list[2] or PROCMGR_AOP_SUBRANGE in func_args_list[2]:
                    self.add_to_secpol("able_priv")
            elif func_args_list[0].startswith("procmgr_event_trigger"):
                self.event_ability(func_args_list)
            elif func_args_list[0].startswith("procmgr_session"):
                if func_args_list[2].isdecimal():
                    comment = ""
                else:
                    comment = " #Provide actual session id (integer value) required by function: " + \
                              self.get_function_call(func_args_list)
                    self.add_to_secpol(''.join(["session:", func_args_list[2], comment]))
            elif func_args_list[0].startswith("setrlimit"):
                comment = self.get_function_call(func_args_list)+\
                    ("please add the ability rlimit with the value updated by this function, rlimit:<limit value "
                     "changed by this function>")
                self.add_to_suggestion(comment)
            elif func_args_list[0].startswith("setgid") or func_args_list[0].startswith("setegid") or \
                    func_args_list[0].startswith("setregid") or func_args_list[0].startswith("setgroups"):
                self.setgid_ability(func_args_list)
            elif func_args_list[0].startswith("setuid") or func_args_list[0].startswith("seteuid") or \
                    func_args_list[0].startswith("setreuid"):
                self.setuid_ability(func_args_list)
            elif func_args_list[0].startswith("procmgr_set_type_id") or \
                    func_args_list[0].startswith("posix_spawnattr_settypeid") or \
                    func_args_list[0].startswith("posix_spawn"):
                self.settypeid_ability(func_args_list)
            elif func_args_list[0].startswith("SignalKillSigval") or func_args_list[0].startswith("SignalKill") or \
                    func_args_list[0].startswith("kill") or func_args_list[0].startswith("sigqueue"):
                self.signal_ability(func_args_list)
            elif func_args_list[0].startswith("sysconf"):
                # define _SC_RCT_SCOID	174
                # define _SC_RCT_MEM   175
                if "174" in func_args_list[1] or "175" in func_args_list[1]:
                    self.add_to_secpol("rconstraint")
            elif func_args_list[0].startswith("ThreadCtl"):
                self.abilities_for_thread_ctl(func_args_list)

        self.add_to_secpol("};")
        print(self.to_secpol_file)
        print("Suggestion file:")
        print(self.to_suggestion_file)

    def provide_secpol_file(self, config_dict):
        # Get the preprocessed file
        get_the_preprocessed_file(config_dict['source_file_path'], config_dict['qcc_path'],
                                  config_dict['include_paths'])
        # Get the function call list along with arguments
        calls = process_c_file("output_file.c", config_dict['entry_function'])
        if os.path.exists("output_file.c"):
            os.remove("output_file.c")

        # Secpol Type declaration for process
        self.secpol_type = ''.join('_' if char == ' ' else char for char in config_dict['process_name'])
        self.secpol_type += '_t'
        self.add_to_secpol("# Type Declaration")
        self.add_to_secpol(''.join(["type ", self.secpol_type, ";"]))

        is_root = config_dict['is_root']
        if is_root == "3":
            self.fcall_list_run_as_root = []
            self.fcall_with_args_as_root = {}
            self.fcall_list_run_as_nonroot = []
            self.fcall_with_args_as_nonroot = {}
            self.__separate_root_nonroot_func_calls(calls)
            self.check_the_required_abilities(0, self.fcall_with_args_as_root)
            self.check_the_required_abilities(1, self.fcall_with_args_as_nonroot)
        else:
            idx = 0
            for functionCall, arguments in calls:
                self.function_call_list.append(functionCall)
                arguments.insert(0, functionCall)
                self.function_with_args[idx] = arguments  # function named followed by arguments
                idx += 1
            if is_root == "1":
                self.check_the_required_abilities(0, self.function_with_args)
            else:
                self.check_the_required_abilities(1, self.function_with_args)

        if not os.path.exists(self.__class__.output_directory):
            os.makedirs(self.__class__.output_directory)

        with open(self.__class__.path_to_output_abilities_file, 'w+') as sec_fd, open(
                self.__class__.path_to_suggestion_file, 'w+') as suggest_fd:
            sec_fd.write(self.to_secpol_file)
            suggest_fd.write(self.to_suggestion_file)


def config_validation(configuration: dict):
    if os.path.exists(configuration['source_file_path']) and os.path.exists(configuration['qcc_path']) and \
            (1 <= int(configuration['is_root']) <= 3) and configuration['entry_function'] is not None and \
            configuration['process_name'] is not None and configuration['include_paths'] is not None:
        return True
    else:
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="python3 SecGenTool.py -c <path_of_config_file>")

    parser.add_argument("-c", "--config_file", type=str, help="The path of the configuration file.", required=True)

    args = parser.parse_args()
    try:
        with open(args.config_file, 'r') as config_fd:
            config = json.load(config_fd)
            if config_validation(config) is True:
                secpolGen = SecpolGenerator()
                secpolGen.provide_secpol_file(config)
            else:
                print("Invalid configuration")

    except(json.JSONDecodeError, FileNotFoundError) as e:
        print("Error reading configuration file", e)
        print("Provide proper configuration file. Please refer ./process_info.config")
