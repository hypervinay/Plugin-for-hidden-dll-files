__author__ = 'vinay'
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
import volatility.win32.tasks as tasks
import volatility.plugins.modscan as modscan
import volatility.plugins.filescan as filescan
import volatility.plugins.malware.psxview as  psxview
import volatility.plugins.taskmods as taskmods
class dllHidden(common.AbstractWindowsCommand):

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                       ("Base", Address),
                       ("Size", Hex),
                       ("LoadCount", Hex),
                       ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for task in data:
            pid = task.UniqueProcessId

            if task.Peb:
                for m in task.get_load_modules():
                    yield (0, [int(pid), Address(m.DllBase), Hex(m.SizeOfImage), Hex(m.LoadCount), str(m.FullDllName or '')])
            else:
                yield (0, [int(pid), Address(0), Hex(0), Hex(0), "Error reading PEB for pid"])
    def render_text(self, outfd, data):
        for task in data:
            pid = task.UniqueProcessId

            outfd.write("*" * 72 + "\n")
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))

            if task.Peb:
                ## REMOVE this after 2.4, since we have the cmdline plugin now
                outfd.write("Command line : {0}\n".format(str(task.Peb.ProcessParameters.CommandLine or '')))
                if task.IsWow64:
                    outfd.write("Note: use ldrmodules for listing DLLs in Wow64 processes\n")
                outfd.write("{0}\n".format(str(task.Peb.CSDVersion or '')))
                outfd.write("\n")
                self.table_header(outfd,
                                  [("Base", "[addrpad]"),
                                   ("Size", "[addr]"),
                                   ("LoadCount", "[addr]"),
                                   ("Path", ""),
                                   ])
                for m in task.get_load_modules():
                    self.table_row(outfd, m.DllBase, m.SizeOfImage, m.LoadCount, str(m.FullDllName or ''))
            else:
                outfd.write("Unable to read PEB for task.\n")

    def calculate(self):
         address_space = utils.load_as(self._config)

         for process in tasks.pslist(address_space):
             pslist_offset=process.obj_offset

         for  p in filescan.PSScan(self._config).calculate():
              psscan_offset=p.obj_offset

         if pslist_offset != psscan_offset:
               tasks_hidden=[taskmods.DllList.virtual_process_from_physical_offset(address_space,psscan_offset)]
         return tasks_hidden


