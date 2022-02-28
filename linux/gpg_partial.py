from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist


class GPGPassphrase(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [  # requirements.TranslationLayerRequirement(name='primary', description='Memory layer to scan'),
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         element_type=int,
                                         description="Process IDs to include (all other processes are excluded)",
                                         optional=True)]

    @classmethod
    def locate_gpg_passphrases(cls, context: interfaces.context.ContextInterface, layer_name: str, sections):
        """Identifies up to 8 bytes of GPG passphrases from a memory image"""
        layer = context.layers[layer_name]
        marker = bytes.fromhex("a6a6a6a6a6a6a6a6")
        for offset in layer.scan(
                context=context,
                scanner=scanners.BytesScanner(needle=marker),
                sections=sections):
            data = layer.read(offset=offset, length=8 + 8 + 8)
            if data[0:8] == marker and data[16:24] == marker:
                passphrase = data[8:16]
                yield format_hints.Hex(offset), str(passphrase, encoding="latin-1", errors="?")

    def _generator(self, tasks):
        # find memory layer name of gpg-agent process
        layer = None
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ["gpg-agent"]:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            layer = self.context.layers[proc_layer_name]
            memory_sections = list(task.get_process_memory_sections(heap_only=False))

            for offset, passphrase in self.locate_gpg_passphrases(self.context,
                                                                  layer.name,
                                                                  memory_sections):
                yield 0, (offset, passphrase)

    def run(self) -> interfaces.renderers.TreeGrid:
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("Partial GPG passphrase (max 8 chars)", str)],
                                  self._generator(pslist.PsList.list_tasks(self.context,
                                                                           self.config['kernel'],
                                                                           filter_func=filter_func))
                                  )
