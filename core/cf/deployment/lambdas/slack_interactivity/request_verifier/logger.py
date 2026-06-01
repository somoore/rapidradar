from os import getenv
import logging

logging.basicConfig(level=logging.ERROR)
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')
