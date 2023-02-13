from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist
from volatility3.framework.exceptions import PagedInvalidAddressException

from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
from time import strftime, gmtime, time

sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]


def valid_schedule(buf):
    return (
        # First round
        buf[16] == (buf[0] ^ sbox[buf[13]] ^ 1)
        and buf[17] == (buf[1] ^ sbox[buf[14]])
        and buf[18] == (buf[2] ^ sbox[buf[15]])
        and buf[19] == (buf[3] ^ sbox[buf[12]])
        # Second round
        and buf[20] == (buf[4] ^ buf[16])
        and buf[21] == (buf[5] ^ buf[17])
        and buf[22] == (buf[6] ^ buf[18])
        and buf[23] == (buf[7] ^ buf[19])
    )


class GPGItem(plugins.PluginInterface):
    '''Extracts and decrypts gpg-agent cache items'''

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # requirements.TranslationLayerRequirement(name='primary', description='Memory layer to scan'),
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         element_type=int,
                                         description="Process IDs to include (all other processes are excluded)",
                                         optional=True),
            requirements.BooleanRequirement(name="fast",
                                            description="Skip large sections",
                                            default=False,
                                            optional=True),
            requirements.IntRequirement(name="epoch",
                                        description='Unix epoch around which the memory capture was performed. This '
                                                    'is important as memory will be searched for timestamps at which '
                                                    'entries were created or accessed by gnupg.',
                                        optional=True)
        ]

    def locate_timestamps(self, context: interfaces.context.ContextInterface, tasks):
        fast_mode = self.config.get("fast")

        # find memory layer name of gpg-agent process
        memory_sections = []
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ["gpg-agent"]:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            layer = self.context.layers[proc_layer_name]
            memory_sections = list(task.get_process_memory_sections(heap_only=False))

            """
            Regex pattern to search for the two time_t (created and accessed) and ttl in memory.
            They are defined like that:

            ```
            struct cache_item_s {
               ITEM next;
               time_t created;
               time_t accessed;  /* Not updated for CACHE_MODE_DATA */
               int ttl;  /* max. lifetime given in seconds, -1 one means infinite */
               struct secret_data_s *pw;
               cache_mode_t cache_mode;
               int restricted;  /* The value of ctrl->restricted is part of the key.  */
               char key[1];
            };
            ```

            """
            epoch = self.config.get("epoch")
            if epoch is None:
                epoch = int(time())
            epoch_start = strftime("%d %b %Y %H:%M:%S", gmtime(epoch))
            end_epoch = (((epoch >> 24) + 1) << 24) - 1
            epoch_end = strftime("%d %b %Y %H:%M:%S", gmtime(end_epoch))
            print(f"Searching from {epoch_start} UTC to {epoch_end} UTC")
            byt = (epoch >> 24).to_bytes(5, "little")
            regex_pattern = b'.{3}' + byt + b'.{3}' + byt + b'\x58\x02\x00\x00'
            byteorder = "little"

            cache_list = []
            for offset in layer.scan(
                    context=context,
                    scanner=scanners.RegExScanner(pattern=regex_pattern),
                    sections=memory_sections):
                data = layer.read(offset=offset, length=8 + 8 + 8 + 8)
                secret_data_s_addr_bytes = data[8 + 8 + 8:]
                created = int.from_bytes(data[0:8], byteorder=byteorder, signed=False)
                accessed = int.from_bytes(data[8:16], byteorder=byteorder, signed=False)

                if accessed < created:
                    print("Error: created timestamp > accessed timestamp")
                    continue

                # convert that address to int
                secret_data_s_addr = int.from_bytes(secret_data_s_addr_bytes, byteorder=byteorder, signed=False)
                if secret_data_s_addr == 0:
                    continue

                # now we try to read at that address, we should find the totallen
                try:
                    secret_length = layer.read(offset=secret_data_s_addr, length=4)
                except PagedInvalidAddressException:
                    continue
                secret_size = int.from_bytes(secret_length, byteorder=byteorder, signed=False)
                secret_bytes = layer.read(offset=secret_data_s_addr + 4, length=secret_size)
                cache_list.append(secret_bytes)

            """
            Decrypt secret_bytes with aes key unwrap

            ```
            struct secret_data_s {
                int  totallen; /* This includes the padding and space for AESWRAP. */
                char data[1];  /* A string.  */
            };
            ```

            """
            for (section_offset, section_length) in memory_sections:
                section_data = layer.read(offset=section_offset, length=section_length, pad=True)
                if fast_mode and section_length > 1000000:
                    continue
                for i in range(0, len(section_data) - 176):
                    if valid_schedule(section_data[i:i + 176]):
                        private_key = section_data[i:i + 16]

                        for secret_bytes in cache_list:
                            plaintext = self.get_plaintext(private_key, secret_bytes)
                            if plaintext is not None:
                                yield format_hints.Hex(offset), private_key.hex(), str(secret_size), plaintext.decode()

    def get_plaintext(self, private_key, secret_bytes):
        try:
            result = aes_key_unwrap(private_key, secret_bytes)
        except InvalidUnwrap:
            result = None  # Integrity check failed we skip this result.
        return result

    def _generator(self, tasks):
        for offset, passphrase, secret_size, plaintext in self.locate_timestamps(self.context, tasks):
            yield 0, (offset, passphrase, secret_size, plaintext)

    def run(self) -> interfaces.renderers.TreeGrid:
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        tasks = pslist.PsList.list_tasks(self.context,
                                         self.config['kernel'],
                                         filter_func=filter_func)
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Private key", str),
                ("Secret size", str),
                ("Plaintext", str)
            ],
            self._generator(tasks))
