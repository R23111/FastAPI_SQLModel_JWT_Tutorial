"""
Basic logging, centralized so sinks/other logging necessities can be customized centrally
"""
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False

formatter = logging.Formatter(
    r"%(asctime)s - %(levelname)-7s %(threadName)-12s [%(filename)s:%(lineno)s - %(funcName)s()] - %(message)s"
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

if __name__ == "__main__":
    logger.info("Info logging test")
    logger.warning("Warning logging test")
    logger.error("Error logging test")
    logger.exception(Exception("Exception logging test"))
