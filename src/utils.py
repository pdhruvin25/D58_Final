import logging

class Utils:
    @staticmethod
    def setup_logger():
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger("PacketSniffer")
