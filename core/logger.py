import sys
from loguru import logger

def setup_logger():
    logger.remove() # Удаляем стандартный хендлер
    
    # Красивый вывод в консоль
    logger.add(
        sys.stderr,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{module}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        level="INFO"
    )
    
    # Лог в файл (для дебага, если нужно)
    logger.add("data/debug.log", rotation="10 MB", level="DEBUG")

# Инициализация при импорте
setup_logger()
