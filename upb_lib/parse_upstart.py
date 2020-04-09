"""
Parse UPStart file and create UPB light/link objects
"""

import logging

from .const import PRODUCTS
from .lights import Light, UpbAddr
from .links import LightLink, Link, LinkAddr

LOG = logging.getLogger(__name__)


def process_upstart_file(pim, filename):
    try:
        with open(filename) as f:
            _process_file(pim, f)
            f.close()
    except EnvironmentError as e:
        LOG.error(f"Cannot open UPStart file '{filename}': {e}")


def _process_file(pim, file):
    for line in file:
        fields = line.strip().split(",")
        if fields[0] == "0":
            # File overview record
            network_id = int(fields[4])
        elif fields[0] == "2":
            _link_definition_record(pim, network_id, fields)
        elif fields[0] == "3":
            _device_definition_record(pim, network_id, fields)
        elif fields[0] == "8":
            _channel_definition_record(pim, network_id, fields)
        elif fields[0] == "4":
            _link_device_definition_record(pim, network_id, fields)
        elif fields[0] == "99":
            _rename_device_record(pim, fields)


def _link_definition_record(pim, network_id, fields):
    link_id = int(fields[1])
    link = Link(LinkAddr(network_id, link_id), pim)
    link.name = fields[2]
    pim.links.add_element(link)


def _device_definition_record(pim, network_id, fields):
    upb_id = int(fields[1])
    number_of_channels = int(fields[8])
    multi_channel = number_of_channels > 1
    for channel in range(0, number_of_channels):
        light = Light(UpbAddr(network_id, upb_id, channel, multi_channel), pim)
        if multi_channel:
            light.name = f"{fields[11]} {fields[12]} {channel}"
        else:
            light.name = f"{fields[11]} {fields[12]}"
        light.version = f"{fields[5]}.{fields[6]}"

        product = f"{fields[3]}/{fields[4]}"
        if product in PRODUCTS:
            light.product = PRODUCTS[product][0]
            light.kind = PRODUCTS[product][1]
        else:
            light.product = product
            light.kind = fields[7]

        pim.lights.add_element(light)


def _channel_definition_record(pim, network_id, fields):
    light_id = UpbAddr(network_id, fields[2], fields[1]).index
    light = pim.lights.elements.get(light_id)
    if light:
        light.dimmable = fields[3] == "1"


def _link_device_definition_record(pim, network_id, fields):
    link_id = int(fields[4])
    if link_id == 255:
        return

    link_idx = LinkAddr(network_id, link_id).index
    light_idx = UpbAddr(network_id, fields[3], fields[1]).index
    dim_level = int(fields[5])
    pim.links[link_idx].add_light(LightLink(light_idx, dim_level))


def _rename_device_record(pim, fields):
    light = pim.lights.elements.get(fields[1])
    if light:
        light.name = fields[2]
