import os
import itertools

import angr
import claripy
#from angr.exploration_techniques import CrashMonitor, Oppologist
from angr.exploration_techniques import Oppologist

# from tracer import QEMURunner

from .qemu_runner import QEMURunner

import logging
l = logging.getLogger('tfuzz.crash_analyzer')

from .cov import replace_input_placeholder

class CrashAnalyzer(object):

    def __init__(self, tprogram, input_file, input_placeholder='@@', target_opts=None, seed=None):
        self.tprogram = tprogram
        self.input_file = os.path.abspath(input_file)
        self.seed = seed
        self.target_opts = target_opts
        self.input_placeholder = input_placeholder

        if target_opts == None or input_placeholder not in target_opts:
            self.stdin_drive = True
            self.target_opts = [os.path.abspath(self.tprogram.program_path)] + \
                               self.target_opts
            self.r = QEMURunner(binary=os.path.abspath(tprogram.program_path),
                                input=file(input_file).read(),
                                seed=seed, argv=target_opts)
        else:
            self.stdin_drive = False
            self.target_opts = [os.path.abspath(self.tprogram.program_path)] + \
                               replace_input_placeholder(self.target_opts, \
                                                         self.input_file, \
                                                         input_placeholder='@@')

            self.r = QEMURunner(binary=self.tprogram.program_path,
                                input='', argv=self.target_opts)

    '''
    This function is extra manually made
    '''
    def collect_constraints(self):

        if not self.r.crash_mode:
            l.info("Input file does not trigger a crash in the target program")
            return None, None, None

        exclude_sim_procedures_list =  ('malloc', 'free', 'calloc', 'realloc')
        self.p = angr.Project(self.tprogram.program_path, exclude_sim_procedures_list=exclude_sim_procedures_list)

        self.p.hook_symbol('set_program_name', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        self.p.hook_symbol('setlocale', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        self.p.hook_symbol('bindtextdomain', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        self.p.hook_symbol('textdomain', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        self.p.hook_symbol('posix_fadvise64', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        self.p.hook_symbol('dcgettext', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        self.p.hook_symbol('atexit', angr.SIM_PROCEDURES['libc']['atexit']())
        prc = angr.SIM_PROCEDURES['stubs']['getopt_long']()
        prc._ret_seq = [ord('d'), -1]
        prc._ret_c = itertools.count()
        prc._optind_addr = 0x080571b4
        self.p.hook_symbol('getopt_long', prc)

        if self.p.loader.main_object.os == 'cgc':
            self.p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])
            state1 = self.p.factory.tracer_state(input_content=file(self.input_file).read(),
                                            magic_content=self.r.magic,
                                            preconstrain_input=True)

        elif self.p.loader.main_object.os.startswith('UNIX'):
            content = {'input_file': self.input_file}
            state1 = self.p.factory.tracer_state(input_content=content,
                                            preconstrain_input=True,
                                            args=self.target_opts)

        # import ipdb; ipdb.set_trace()

        crashing_block = self.p.factory.block(self.r.crash_addr)
        self.collected_constraints = []
        self.offending_constraints = []
        def inspect_func(state):

            # import ipdb; ipdb.set_trace()
            sc = state.added
            if not state.satisfiable() or len(sc) == 0:
                return

            # constraints from lava_get
            if state.addr in [0x8049554, 0x804955a]:
                return

            # crashing addr too ?
            if state.addr in [0x9067084]:
                return

            # crashing addr
            if state.addr in crashing_block.instruction_addrs:
                return
            # if state.addr in [0x804cd8e, 0x804cde1]:
            # return

            # if 0x9067084 == state.addr:
            #     import ipdb; ipdb.set_trace()

            # constraints from fileno
            # if state.addr in [0x9065510]:
            #     return

            # import ipdb; ipdb.set_trace()
            # print("[%s]: %s" % (hex(state.addr), str(sc)))

            # if state.addr in [0x804b32d, 0x804c778]:
            if state.addr in [0x804b32d]:
                self.offending_constraints.extend(sc)
                return

            if state.addr in self.tprogram.c_all_instr_addrs:
                assert(len(sc) == 1)
                # print ("============== NEG ==============")
                self.collected_constraints.append(claripy.Not(sc[0]))
            else:
                self.collected_constraints.extend(sc)

        # state1.inspect.b('exit', when=angr.BP_AFTER, action=exit_inspect)
        state1.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_func)
        self.simgr = self.p.factory.simgr(state1,
                                     save_unsat=False,
                                     hierarchy=False,
                                     save_unconstrained=False)
        self.t = angr.exploration_techniques.Tracer(trace=self.r.trace)

        self.simgr.use_technique(self.t)
        self.simgr.use_technique(angr.exploration_techniques.Oppologist())

        self.simgr.run()

        self.pred_state, self.crash_state = self.t.predecessors[-1], self.simgr.traced[0]

        return self.collected_constraints, self.pred_state, self.crash_state

    def _add_relaxed_offending_constraints(self, state):
        for oc in self.offending_constraints:
            roc = self._relax_offending_constraint(oc)
            print(("Adding %s" % (roc)))
            state.add_constraints(roc)

            if not state.satisfiable():
                print("%s causes state unsatisfiable" % (oc))
                return False

        return True

    def _relax_offending_constraint(self, c):
        arg0 = c.args[0]
        arg00 = arg0.args[0]
        t_byte = arg00.args[1]
        arg01 = arg0.args[1]
        arg1 = c.args[1]

        diff = arg1 - arg01
        diff_val = self.pred_state.se.eval(diff)

        up_l = claripy.And(t_byte >= ord('A'), t_byte <= ord('Z'))
        low_l = claripy.And(t_byte >= ord('a'), t_byte <= ord('z'))
        num = claripy.And(t_byte >= ord('0'), t_byte <= ord('9'))
        plus = t_byte == ord('+')
        slash = t_byte == ord('/')
        c1 = claripy.Or(up_l, low_l, num, plus, slash)

        if (diff_val >= ord('A') and diff_val <= ord('Z')) or \
           (diff_val >= ord('a') and diff_val <= ord('z')) or \
           (diff_val >= ord('0') and diff_val <= ord('9')) or \
           diff_val == ord('+') or diff_val == ord('/'):

            return c1

        return claripy.Not(c1)


    def recover_data_from_preconstraints(self):
        preconstraints = self.pred_state.preconstrainer.preconstraints
        # we hope that the order is correct
        assert len(preconstraints) > 0
        x = preconstraints[0].args[0]

        for i in range(1, len(preconstraints)):
            x = claripy.Concat(x, preconstraints[i].args[0])

        return x

    def verify(self):
        if self.stdin_drive:
            simf = self.pred_state.posix.files[0]
            data = simf.all_bytes()
        else:
            simf = self.pred_state.posix.fs[self.input_file]
            data = simf.all_bytes()

        empty_state = self.p.factory.blank_state()

        empty_state.add_constraints(*self.collected_constraints)
        sat = empty_state.satisfiable()
        if sat:
            sol = empty_state.solver.eval(data, cast_to=str)
        else:
            sol = None

        return sat, sol
