import collections
from enum import Enum
from unittest import result

from sword.utils.output import error
from sword.network_modular.host import Host

class Command_Parser(object):
    class Flag_Type(Enum):
        COMMON_FLAG = 1
        PARAMETERIZED_FLAG = 2

    class Subparser_Type(Enum):
        NO_PMT_SUBP = 1
        ESS_PMT_SUBP = 2
        NON_ESS_PMT_SUBP = 3
    
    command_subparser = collections.namedtuple('command_subparser', 'name, handle, type')
    command_flag = collections.namedtuple('command_flags', 'id, name, type')

    def __init__(self):
        self._flags = []
        self._flag_ids = []
        self._subparser = []

    def add_subparser(self, name, type, handle):
        subparser = Command_Parser.command_subparser(
            name=name,
            type=type,
            handle=handle)

        self._subparser.append(subparser)

    def add_flag(self, id, name, type):
        flag = Command_Parser.command_flag(
            id=id,
            name=name,
            type=type)

        self._flags.append(flag)
        self._flag_ids.append(id)
    
    def parser(self, command: list): #command -> list
        for sp in self._subparser:
            if sp.name == command[0]:
                
                #----Subparser_Type = NO_PMT_SUBP
                if sp.type == Command_Parser.Subparser_Type.NO_PMT_SUBP:
                    sp.handle()
                    return
                
                #----Subparser_Type = ESS_PMT_SUBP
                elif sp.type == Command_Parser.Subparser_Type.ESS_PMT_SUBP:
                    if len(command) == 1:
                        error(f'{sp.name} need argument.')
                        
                    else:
                        result: dict = self._parser_arguments(command[0:])
                        if result == None:
                            error('argument error.')

                        else:
                            sp.handle(result)
                    return
                
                #----Subparser_Type = NO_ESS_PMT_SUBP
                elif sp.type == Command_Parser.Subparser_Type.NON_ESS_PMT_SUBP:
                    if len(command) == 1:
                        sp.handle()

                    else:
                        result = self._parser_arguments(command[0:])
                        sp.handle(result)
                    return

            
        error(f'Unknow command \'{command[0]}\'')
            
    def _parser_arguments(self, args: list):
        result_dict = dict()
        for i, arg in enumerate(args):
            for flag in self._flags:
                if flag.id == arg:
                    if flag.type == Command_Parser.Flag_Type.COMMON_FLAG:
                        result_dict.setdefault(flag.name, True)
                        continue
                            
                    elif flag.type == Command_Parser.Flag_Type.PARAMETERIZED_FLAG:
                        if len(args) == i + 1:
                            result_dict.setdefault(flag.name, None)
                        else:                            
                            if args[i+1] in self._flag_ids:
                                result_dict.setdefault(flag.name, None)

                            else:    
                                result_dict.setdefault(flag.name, args[i+1])
        return result_dict #Example: result_dict = {'target_ip': '192.168.2.1,192.168.2.14,...'}

if __name__ == '__main__':
    def handle(result = None):
        print('hey')
        if result != None:
            print(result)
    
    def arpsf_handle(result):
        print(result)

    parser = Command_Parser()
    parser.add_subparser(
        name='scan',
        type=Command_Parser.Subparser_Type.NO_PMT_SUBP,
        handle=handle)

    parser.add_subparser(
        name='arpsf',
        type=Command_Parser.Subparser_Type.ESS_PMT_SUBP,
        handle=arpsf_handle
    )
    parser.add_flag(
        name='ip',
        id='-p',
        type=Command_Parser.Flag_Type.PARAMETERIZED_FLAG
    )

    command = input('>>> ')
    parser.parser(command.split())